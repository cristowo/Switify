#include "connect_dealer.hpp"

#include "Crypto.h"
#include "NXConsoleLog.h"
#include "X509Bundle.h"
#include "spotify_engine.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <nlohmann/json.hpp>
#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <random>
#include <thread>

namespace switify::phase2 {
namespace {

using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;

constexpr const char* DealerHost = "dealer.spotify.com";
constexpr size_t MaxMessage = 512u << 10;  // a cluster with a long queue fits; more is dropped (held in a few copies while decoded: the heap is 4 MiB)
constexpr auto PingInterval = std::chrono::seconds(30);
constexpr auto PongTimeout = std::chrono::seconds(40);
constexpr auto UpgradeTimeout = std::chrono::seconds(15);

// PutStateReason (connect.proto)
constexpr int NewDevice = 3, PlayerStateChanged = 4, VolumeChanged = 5, BecameInactive = 7;

// --- protobuf, by hand (the few fields used; connect.proto / player.proto)
void varint(std::vector<uint8_t>& out, uint64_t v) {
  while (v >= 0x80) {
    out.push_back(static_cast<uint8_t>(v) | 0x80);
    v >>= 7;
  }
  out.push_back(static_cast<uint8_t>(v));
}
void key(std::vector<uint8_t>& out, uint32_t field, uint32_t wire) { varint(out, (uint64_t(field) << 3) | wire); }
void uintField(std::vector<uint8_t>& out, uint32_t field, uint64_t v) {
  key(out, field, 0);
  varint(out, v);
}
void boolField(std::vector<uint8_t>& out, uint32_t field, bool v) { if (v) uintField(out, field, 1); }
void bytesField(std::vector<uint8_t>& out, uint32_t field, const void* data, size_t size) {
  key(out, field, 2);
  varint(out, size);
  const auto* p = static_cast<const uint8_t*>(data);
  out.insert(out.end(), p, p + size);
}
void stringField(std::vector<uint8_t>& out, uint32_t field, const std::string& s) {
  if (!s.empty()) bytesField(out, field, s.data(), s.size());
}
void messageField(std::vector<uint8_t>& out, uint32_t field, const std::vector<uint8_t>& m) {
  bytesField(out, field, m.data(), m.size());
}
void doubleField(std::vector<uint8_t>& out, uint32_t field, double v) {
  key(out, field, 1);
  uint8_t raw[8];
  std::memcpy(raw, &v, 8);  // (little-endian, as protobuf wants)
  out.insert(out.end(), raw, raw + 8);
}

// Reads the fields of one message: f(field, wire, varint value, bytes).
template <typename F>
bool readMessage(const uint8_t* p, size_t size, F&& f) {
  size_t i = 0;
  auto rv = [&](uint64_t& v) {
    v = 0;
    for (int shift = 0; shift < 64 && i < size; shift += 7) {
      const uint8_t b = p[i++];
      v |= uint64_t(b & 0x7f) << shift;
      if (!(b & 0x80)) return true;
    }
    return false;
  };
  while (i < size) {
    uint64_t k = 0;
    if (!rv(k)) return false;
    const uint32_t field = uint32_t(k >> 3), wire = uint32_t(k & 7);
    if (wire == 0) {
      uint64_t v = 0;
      if (!rv(v)) return false;
      f(field, wire, v, nullptr, 0);
    } else if (wire == 2) {
      uint64_t len = 0;
      if (!rv(len) || len > size - i) return false;
      f(field, wire, 0, p + i, size_t(len));
      i += size_t(len);
    } else if (wire == 1) {
      if (i + 8 > size) return false;
      i += 8;
    } else if (wire == 5) {
      if (i + 4 > size) return false;
      i += 4;
    } else {
      return false;
    }
  }
  return true;
}

std::string gunzip(const std::string& in) {
  z_stream z{};
  if (inflateInit2(&z, 16 + MAX_WBITS) != Z_OK) return {};
  z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  z.avail_in = static_cast<uInt>(in.size());
  std::string out;
  char buf[4096];
  int rc = Z_OK;
  while (rc == Z_OK) {
    z.next_out = reinterpret_cast<Bytef*>(buf);
    z.avail_out = sizeof(buf);
    rc = inflate(&z, Z_NO_FLUSH);
    out.append(buf, sizeof(buf) - z.avail_out);
    if (out.size() > MaxMessage) {
      rc = Z_DATA_ERROR;
      break;
    }
  }
  inflateEnd(&z);
  return rc == Z_STREAM_END ? out : std::string();
}

std::string unbase64(const std::string& s) {
  const auto bytes = CryptoMbedTLS::base64Decode(s);
  return std::string(bytes.begin(), bytes.end());
}

std::string randomHex(size_t bytes) {
  static std::mt19937_64 rng{std::random_device{}() ^ static_cast<uint64_t>(Clock::now().time_since_epoch().count())};
  static const char* hex = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < bytes; ++i) {
    const auto b = static_cast<uint8_t>(rng());
    out += hex[b >> 4];
    out += hex[b & 15];
  }
  return out;
}

}  // namespace

struct ConnectDealer::Tls {
  mbedtls_net_context net;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  Tls() {
    mbedtls_net_init(&net);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
  }
  ~Tls() {
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&net);
  }
};

ConnectDealer::ConnectDealer(SpotifyEngine& engine) : engine(engine) {}
ConnectDealer::~ConnectDealer() { close("service stopping"); }

void ConnectDealer::playerChanged() {
  if (active) dirty = true;
}

void ConnectDealer::tick() {
  const auto now = Clock::now();
  if (phase == Phase::Idle) {
    if (engine.state() != SpotifyEngine::State::Ready || now < retryAt) return;
    if (!connect()) {
      retryAt = now + backoff;
      backoff = std::min<std::chrono::seconds>(backoff * 2, std::chrono::seconds(300));
    }
    return;
  }
  bool ok = true;
  if (phase == Phase::Handshake) ok = stepHandshake();
  else if (phase == Phase::Upgrade) ok = stepUpgrade();
  else ok = stepOpen();
  if (!ok) return;
  // What changed here (the next song, a pause from the overlay or HOME) is
  // the phone's to know too.
  if (phase == Phase::Open && active) {
    const auto np = engine.nowPlaying();
    const std::string seen = np.uri + (np.paused ? "|p" : "|r") + (np.shuffle ? "s" : "-") +
                             char('0' + int(np.repeatMode));
    if (seen != lastSeen) {
      lastSeen = seen;
      dirty = true;
    }
  }
  // State pushes: at most one a second, the latest state.
  if (phase == Phase::Open && dirty && !connectionId.empty() && now - lastPush > std::chrono::seconds(1)) {
    dirty = false;
    pushState(PlayerStateChanged);
  }
}

bool ConnectDealer::connect() {
  const std::string token = engine.connectAccessToken();  // (cached; a request when it's due)
  deviceId = engine.connectDeviceId();
  if (token.empty() || deviceId.empty()) {
    nxlog::push("Connect: no token or device id yet");
    return false;
  }
  tls = std::make_unique<Tls>();
  int rc = mbedtls_ctr_drbg_seed(&tls->drbg, mbedtls_entropy_func, &tls->entropy,
                                 reinterpret_cast<const unsigned char*>("switify-dealer"), 14);
  if (rc == 0) rc = mbedtls_net_connect(&tls->net, DealerHost, "443", MBEDTLS_NET_PROTO_TCP);
  if (rc == 0) rc = mbedtls_net_set_nonblock(&tls->net);
  if (rc == 0)
    rc = mbedtls_ssl_config_defaults(&tls->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc == 0) {
    // As bell's TLSSocket (the access point's): verified when a bundle is loaded.
    bell::X509Bundle::attach(&tls->conf);
    mbedtls_ssl_conf_authmode(&tls->conf, bell::X509Bundle::shouldVerify() ? MBEDTLS_SSL_VERIFY_REQUIRED
                                                                            : MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&tls->conf, mbedtls_ctr_drbg_random, &tls->drbg);
    rc = mbedtls_ssl_setup(&tls->ssl, &tls->conf);
  }
  if (rc == 0) rc = mbedtls_ssl_set_hostname(&tls->ssl, DealerHost);
  if (rc != 0) {
    nxlog::pushf("Connect: dealer connection failed (%d)", rc);
    tls.reset();
    return false;
  }
  mbedtls_ssl_set_bio(&tls->ssl, &tls->net, mbedtls_net_send, mbedtls_net_recv, nullptr);
  rx.clear();
  fragments.clear();
  connectionId.clear();
  phase = Phase::Handshake;
  upgradeSent = Clock::now();
  // The upgrade goes out once TLS is up (stepHandshake), with this token.
  sessionId = randomHex(16);
  fragments = token;  // (kept here until then)
  return true;
}

void ConnectDealer::close(const char* why) {
  if (phase == Phase::Idle) return;
  nxlog::pushf("Connect: dealer closed (%s)", why);
  if (tls) {
    if (phase == Phase::Open) mbedtls_ssl_close_notify(&tls->ssl);
    tls.reset();
  }
  phase = Phase::Idle;
  connectionId.clear();
  rx.clear();
  fragments.clear();
  retryAt = Clock::now() + backoff;
  backoff = std::min<std::chrono::seconds>(backoff * 2, std::chrono::seconds(300));
}

bool ConnectDealer::stepHandshake() {
  const int rc = mbedtls_ssl_handshake(&tls->ssl);
  if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
    if (Clock::now() - upgradeSent > UpgradeTimeout) {
      close("TLS handshake timed out");
      return false;
    }
    return true;
  }
  if (rc != 0) {
    char line[48];
    std::snprintf(line, sizeof(line), "TLS handshake failed (-0x%04X)", unsigned(-rc));
    close(line);
    return false;
  }
  const std::string token = fragments;
  fragments.clear();
  std::string keyBytes;
  for (int i = 0; i < 16; ++i) keyBytes += char(std::rand() & 0xff);
  const std::string wsKey = CryptoMbedTLS::base64Encode(std::vector<uint8_t>(keyBytes.begin(), keyBytes.end()));
  const std::string request = std::string("GET /?access_token=") + token + " HTTP/1.1\r\n"
                              "Host: " + DealerHost + "\r\n"
                              "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                              "Sec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\n"
                              "User-Agent: Spotify/127700358 Linux/0 (Switify)\r\n\r\n";
  if (!writeAll(reinterpret_cast<const uint8_t*>(request.data()), request.size())) {
    close("upgrade request not sent");
    return false;
  }
  phase = Phase::Upgrade;
  upgradeSent = Clock::now();
  return true;
}

bool ConnectDealer::stepUpgrade() {
  if (!readSome()) {
    close("closed during the upgrade");
    return false;
  }
  const size_t end = rx.find("\r\n\r\n");
  if (end == std::string::npos) {
    if (Clock::now() - upgradeSent > UpgradeTimeout || rx.size() > 16384) {
      close("no upgrade answer");
      return false;
    }
    return true;
  }
  const std::string head = rx.substr(0, rx.find("\r\n"));
  if (head.find(" 101") == std::string::npos) {
    nxlog::pushf("Connect: dealer refused: %.80s", head.c_str());
    close("upgrade refused");
    return false;
  }
  rx.erase(0, end + 4);
  phase = Phase::Open;
  lastPing = lastPong = Clock::now();
  backoff = std::chrono::seconds(5);
  nxlog::push("Connect: dealer open");
  return stepOpen();
}

bool ConnectDealer::readSome() {
  uint8_t buf[4096];
  for (int i = 0; i < 64; ++i) {  // (at most 256 KiB a tick)
    const int rc = mbedtls_ssl_read(&tls->ssl, buf, sizeof(buf));
    if (rc > 0) {
      rx.append(reinterpret_cast<const char*>(buf), size_t(rc));
      if (rx.size() > MaxMessage + 16) return false;
      continue;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return true;
    return false;  // 0: closed; < 0: an error
  }
  return true;
}

bool ConnectDealer::writeAll(const uint8_t* data, size_t size) {
  const auto deadline = Clock::now() + std::chrono::seconds(5);
  while (size > 0) {
    const int rc = mbedtls_ssl_write(&tls->ssl, data, size);
    if (rc > 0) {
      data += rc;
      size -= size_t(rc);
    } else if (rc == MBEDTLS_ERR_SSL_WANT_WRITE || rc == MBEDTLS_ERR_SSL_WANT_READ) {
      if (Clock::now() > deadline) return false;
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    } else {
      return false;
    }
  }
  return true;
}

bool ConnectDealer::sendFrame(uint8_t opcode, const std::string& payload) {
  std::vector<uint8_t> frame;
  frame.push_back(0x80 | opcode);
  const size_t n = payload.size();
  if (n < 126) {
    frame.push_back(0x80 | uint8_t(n));
  } else if (n < 65536) {
    frame.push_back(0x80 | 126);
    frame.push_back(uint8_t(n >> 8));
    frame.push_back(uint8_t(n));
  } else {
    frame.push_back(0x80 | 127);
    for (int i = 7; i >= 0; --i) frame.push_back(uint8_t(uint64_t(n) >> (8 * i)));
  }
  uint8_t mask[4];
  for (auto& m : mask) m = uint8_t(std::rand());
  frame.insert(frame.end(), mask, mask + 4);
  for (size_t i = 0; i < n; ++i) frame.push_back(uint8_t(payload[i]) ^ mask[i & 3]);
  return writeAll(frame.data(), frame.size());
}

bool ConnectDealer::stepOpen() {
  if (!readSome()) {
    close("connection lost");
    return false;
  }
  while (rx.size() >= 2) {
    const auto* p = reinterpret_cast<const uint8_t*>(rx.data());
    const bool fin = p[0] & 0x80;
    const uint8_t op = p[0] & 0x0f;
    const bool masked = p[1] & 0x80;
    uint64_t len = p[1] & 0x7f;
    size_t head = 2;
    if (len == 126) {
      if (rx.size() < 4) break;
      len = (uint64_t(p[2]) << 8) | p[3];
      head = 4;
    } else if (len == 127) {
      if (rx.size() < 10) break;
      len = 0;
      for (int i = 0; i < 8; ++i) len = (len << 8) | p[2 + i];
      head = 10;
    }
    if (len > MaxMessage) {
      close("message too large");
      return false;
    }
    const size_t maskAt = head;
    if (masked) head += 4;
    if (rx.size() < head + len) break;
    std::string payload = rx.substr(head, size_t(len));
    if (masked)
      for (size_t i = 0; i < payload.size(); ++i) payload[i] ^= rx[maskAt + (i & 3)];
    rx.erase(0, head + size_t(len));
    if (op == 0x8) {
      close("dealer said goodbye");
      return false;
    } else if (op == 0x9) {
      sendFrame(0xA, payload);
    } else if (op == 0x1 || op == 0x2 || op == 0x0) {
      if (op != 0x0) fragments = std::move(payload);
      else fragments += payload;
      if (fragments.size() > MaxMessage) {
        close("message too large");
        return false;
      }
      if (fin) {
        const std::string text = std::move(fragments);
        fragments.clear();
        handleText(text);
        if (phase != Phase::Open) return false;
      }
    }
  }
  const auto now = Clock::now();
  if (now - lastPong > PongTimeout + PingInterval) {
    close("no pong");
    return false;
  }
  if (now - lastPing > PingInterval) {
    lastPing = now;
    if (!sendFrame(0x1, "{\"type\":\"ping\"}")) {
      close("ping not sent");
      return false;
    }
  }
  return true;
}

void ConnectDealer::handleText(const std::string& text) {
  Json m;
  try {
    m = Json::parse(text);
  } catch (...) {
    nxlog::push("Connect: unreadable dealer message");
    return;
  }
  const std::string type = m.value("type", "");
  if (type == "pong") {
    lastPong = Clock::now();
    return;
  }
  auto headerOf = [&](const char* name) -> std::string {
    if (!m.contains("headers") || !m["headers"].is_object()) return {};
    const auto it = m["headers"].find(name);
    return it != m["headers"].end() && it->is_string() ? it->get<std::string>() : std::string();
  };
  const bool gzip = headerOf("Transfer-Encoding") == "gzip";
  if (type == "message") {
    std::string payload;
    if (m.contains("payloads") && m["payloads"].is_array() && !m["payloads"].empty() && m["payloads"][0].is_string())
      payload = unbase64(m["payloads"][0].get<std::string>());
    handleMessage(m.value("uri", ""), payload, gzip, headerOf("Spotify-Connection-Id"));
  } else if (type == "request") {
    const std::string key = m.value("key", "");
    std::string body;
    if (m.contains("payload") && m["payload"].is_object() && m["payload"].contains("compressed"))
      body = unbase64(m["payload"].value("compressed", ""));
    if (gzip) body = gunzip(body);
    bool ok = false;
    try {
      ok = !body.empty() && handleCommand(body);
    } catch (const std::exception& error) {
      nxlog::pushf("Connect: command failed: %s", error.what());
    }
    reply(key, ok);
    if (ok) pushState(PlayerStateChanged);
  }
}

void ConnectDealer::handleMessage(const std::string& uri, const std::string& raw, bool gzip,
                                  const std::string& connId) {
  if (uri.rfind("hm://pusher/v1/connections/", 0) == 0) {
    if (connId.empty()) return;
    connectionId = connId;
    nxlog::push("Connect: connection id received; announcing this device");
    pushState(NewDevice);
    return;
  }
  const std::string payload = gzip ? gunzip(raw) : raw;
  if (uri.rfind("hm://connect-state/v1/connect/volume", 0) == 0) {
    int64_t volume = -1;
    readMessage(reinterpret_cast<const uint8_t*>(payload.data()), payload.size(),
                [&](uint32_t f, uint32_t w, uint64_t v, const uint8_t*, size_t) {
                  if (f == 1 && w == 0) volume = int64_t(v);
                });
    if (volume >= 0) {
      engine.setVolume(std::clamp<float>(float(volume) / 65535.f, 0.f, 1.f));
      pushState(VolumeChanged);
    }
  } else if (uri.rfind("hm://connect-state/v1/cluster", 0) == 0) {
    // ClusterUpdate.cluster(1).active_device_id(2): another device took over.
    std::string activeId;
    readMessage(reinterpret_cast<const uint8_t*>(payload.data()), payload.size(),
                [&](uint32_t f, uint32_t w, uint64_t, const uint8_t* b, size_t n) {
                  if (f != 1 || w != 2) return;
                  readMessage(b, n, [&](uint32_t f2, uint32_t w2, uint64_t, const uint8_t* b2, size_t n2) {
                    if (f2 == 2 && w2 == 2) activeId.assign(reinterpret_cast<const char*>(b2), n2);
                  });
                });
    if (active && !activeId.empty() && activeId != deviceId) {
      active = false;
      nxlog::push("Connect: another device took over");
      if (!engine.nowPlaying().paused) engine.playPause();
    }
  }
}

bool ConnectDealer::handleCommand(const std::string& text) {
  const Json request = Json::parse(text);
  lastCommandId = request.value("message_id", 0u);
  lastCommandFrom = request.value("sent_by_device_id", "");
  if (!request.contains("command")) return false;
  const Json& c = request["command"];
  const std::string endpoint = c.value("endpoint", "");
  nxlog::pushf("Connect: %s from the phone", endpoint.c_str());
  const auto now = engine.nowPlaying();
  auto boolValue = [&](const Json& j, const char* name, bool fallback) {
    return j.contains(name) && j[name].is_boolean() ? j[name].get<bool>() : fallback;
  };
  if (endpoint == "transfer") {
    const std::string data = unbase64(c.value("data", ""));
    std::string trackUri, ctxUri;
    int64_t timestamp = 0, position = 0;
    bool paused = false, shuffle = false, repeatContext = false, repeatTrack = false;
    const auto* p = reinterpret_cast<const uint8_t*>(data.data());
    readMessage(p, data.size(), [&](uint32_t f, uint32_t w, uint64_t, const uint8_t* b, size_t n) {
      if (w != 2) return;
      if (f == 1) {  // options
        readMessage(b, n, [&](uint32_t f2, uint32_t, uint64_t v, const uint8_t*, size_t) {
          if (f2 == 1) shuffle = v;
          if (f2 == 2) repeatContext = v;
          if (f2 == 3) repeatTrack = v;
        });
      } else if (f == 2) {  // playback
        readMessage(b, n, [&](uint32_t f2, uint32_t w2, uint64_t v, const uint8_t* b2, size_t n2) {
          if (f2 == 1 && w2 == 0) timestamp = int64_t(v);
          if (f2 == 2 && w2 == 0) position = int64_t(int32_t(v));
          if (f2 == 4 && w2 == 0) paused = v;
          if (f2 == 5 && w2 == 2)
            readMessage(b2, n2, [&](uint32_t f3, uint32_t w3, uint64_t, const uint8_t* b3, size_t n3) {
              if (f3 == 1 && w3 == 2) trackUri.assign(reinterpret_cast<const char*>(b3), n3);
            });
        });
      } else if (f == 3) {  // current_session.context(2).uri(1)
        readMessage(b, n, [&](uint32_t f2, uint32_t w2, uint64_t, const uint8_t* b2, size_t n2) {
          if (f2 == 2 && w2 == 2)
            readMessage(b2, n2, [&](uint32_t f3, uint32_t w3, uint64_t, const uint8_t* b3, size_t n3) {
              if (f3 == 1 && w3 == 2) ctxUri.assign(reinterpret_cast<const char*>(b3), n3);
            });
        });
      }
    });
    if (!paused && timestamp > 0) {
      const int64_t elapsed = int64_t(engine.spotifyTimeMs()) - timestamp;
      if (elapsed > 0 && elapsed < 60'000) position += elapsed;
    }
    nxlog::pushf("Connect: transfer of %s at %lld ms%s", trackUri.c_str(), (long long)position,
                 paused ? " (paused)" : "");
    if (trackUri.empty() && ctxUri.empty()) return false;
    contextUri = ctxUri;
    engine.playContext(ctxUri, trackUri, uint32_t(std::max<int64_t>(0, position)), paused);
    engine.setRepeatMode(repeatTrack ? SpotifyEngine::RepeatMode::One
                         : repeatContext ? SpotifyEngine::RepeatMode::All : SpotifyEngine::RepeatMode::Off);
    (void)shuffle;  // (the engine's own shuffle reorders what it loaded: left as it is)
    active = true;
    activeSince = engine.spotifyTimeMs();
    playbackId = randomHex(16);
    return true;
  }
  if (endpoint == "play") {
    const std::string ctxUri = c.contains("context") && c["context"].is_object() ? c["context"].value("uri", "") : "";
    std::string trackUri;
    bool paused = false;
    if (c.contains("options") && c["options"].is_object()) {
      const Json& o = c["options"];
      paused = boolValue(o, "initially_paused", false);
      if (o.contains("skip_to") && o["skip_to"].is_object()) trackUri = o["skip_to"].value("track_uri", "");
    }
    if (ctxUri.empty() && trackUri.empty()) return false;
    contextUri = ctxUri;
    engine.playContext(ctxUri, trackUri, 0, paused);
    active = true;
    activeSince = engine.spotifyTimeMs();
    playbackId = randomHex(16);
    return true;
  }
  if (endpoint == "pause") {
    if (!now.paused) engine.playPause();
    return true;
  }
  if (endpoint == "resume") {
    if (now.paused) engine.playPause();
    return true;
  }
  if (endpoint == "skip_next") {
    engine.next();
    return true;
  }
  if (endpoint == "skip_prev") {
    engine.previous();
    return true;
  }
  if (endpoint == "seek_to") {
    int64_t target = c.contains("value") && c["value"].is_number() ? c["value"].get<int64_t>() : c.value("position", int64_t(0));
    if (c.value("relative", "") == "current") target += int64_t(now.positionMs);
    engine.seekToMs(uint32_t(std::max<int64_t>(0, target)));
    return true;
  }
  if (endpoint == "set_shuffling_context") {
    if (boolValue(c, "value", now.shuffle) != now.shuffle) engine.toggleShuffle();
    return true;
  }
  if (endpoint == "set_repeating_context" || endpoint == "set_repeating_track") {
    const bool on = boolValue(c, "value", false);
    const bool track = endpoint == "set_repeating_track";
    engine.setRepeatMode(on ? (track ? SpotifyEngine::RepeatMode::One : SpotifyEngine::RepeatMode::All)
                            : SpotifyEngine::RepeatMode::Off);
    return true;
  }
  if (endpoint == "set_options") {
    if (c.contains("shuffling_context") && c["shuffling_context"].is_boolean() &&
        c["shuffling_context"].get<bool>() != now.shuffle)
      engine.toggleShuffle();
    const bool track = boolValue(c, "repeating_track", false), context = boolValue(c, "repeating_context", false);
    if (c.contains("repeating_track") || c.contains("repeating_context"))
      engine.setRepeatMode(track ? SpotifyEngine::RepeatMode::One
                           : context ? SpotifyEngine::RepeatMode::All : SpotifyEngine::RepeatMode::Off);
    return true;
  }
  // Queue edits, context updates, playback speed, sleep timers: accepted, not done.
  return endpoint == "add_to_queue" || endpoint == "set_queue" || endpoint == "update_context" ||
         endpoint == "set_playback_speed" || endpoint == "set_sleep_timer";
}

void ConnectDealer::reply(const std::string& key, bool success) {
  if (key.empty() || phase != Phase::Open) return;
  sendFrame(0x1, std::string("{\"type\":\"reply\",\"key\":\"") + key + "\",\"payload\":{\"success\":" +
                     (success ? "true" : "false") + "}}");
}

void ConnectDealer::pushState(int reason) {
  if (connectionId.empty()) return;
  lastPush = Clock::now();
  const auto now = engine.nowPlaying();
  const uint64_t timeMs = engine.spotifyTimeMs();

  std::vector<uint8_t> caps;  // Capabilities (go-librespot's set, less what isn't done here)
  boolField(caps, 2, true);    // can_be_player
  boolField(caps, 5, true);    // gaia_eq_connect_id
  boolField(caps, 7, true);    // is_observable
  uintField(caps, 8, 64);      // volume_steps
  stringField(caps, 9, "audio/track");
  stringField(caps, 9, "audio/episode");
  boolField(caps, 10, true);   // command_acks
  boolField(caps, 15, true);   // supports_playlist_v2
  boolField(caps, 16, true);   // is_controllable
  boolField(caps, 18, true);   // supports_set_backend_metadata
  boolField(caps, 19, true);   // supports_transfer_command
  boolField(caps, 20, true);   // supports_command_request
  boolField(caps, 23, true);   // supports_gzip_pushes
  boolField(caps, 25, true);   // supports_set_options_command

  std::vector<uint8_t> info;  // DeviceInfo
  boolField(info, 1, true);                                                   // can_play
  uintField(info, 2, uint64_t(std::clamp(now.volume, 0.f, 1.f) * 65535.f));  // volume
  stringField(info, 3, "Switify");                                            // name
  messageField(info, 4, caps);
  stringField(info, 6, "Switify 0.7.1");                                      // device_software_version
  uintField(info, 7, 9);                                                      // device_type: GAME_CONSOLE
  stringField(info, 9, "3.2.6");                                              // spirc_version
  stringField(info, 10, deviceId);
  stringField(info, 14, "Nintendo");                                          // brand
  stringField(info, 15, "Switch");                                            // model
  stringField(info, 23, "premium");                                           // license

  std::vector<uint8_t> player;  // PlayerState
  if (active && now.hasTrack) {
    uintField(player, 1, timeMs);              // timestamp
    stringField(player, 2, contextUri);        // context_uri
    std::vector<uint8_t> track;
    stringField(track, 1, now.uri);
    stringField(track, 6, "context");          // provider
    messageField(player, 7, track);
    stringField(player, 8, playbackId);
    doubleField(player, 9, now.paused ? 0.0 : 1.0);  // playback_speed
    uintField(player, 10, now.positionMs);     // position_as_of_timestamp
    uintField(player, 11, now.durationMs);     // duration
    boolField(player, 12, true);               // is_playing (a session is on)
    boolField(player, 13, now.paused);         // is_paused
    std::vector<uint8_t> options;
    boolField(options, 1, now.shuffle);
    boolField(options, 2, now.repeatMode == SpotifyEngine::RepeatMode::All);
    boolField(options, 3, now.repeatMode == SpotifyEngine::RepeatMode::One);
    messageField(player, 16, options);
    stringField(player, 23, sessionId);
  }

  std::vector<uint8_t> device;
  messageField(device, 1, info);
  if (!player.empty()) messageField(device, 2, player);

  std::vector<uint8_t> body;  // PutStateRequest
  messageField(body, 2, device);
  uintField(body, 3, 2);                         // member_type: CONNECT_STATE
  boolField(body, 4, active);                    // is_active
  uintField(body, 5, uint64_t(reason));
  if (lastCommandId) {
    stringField(body, 7, lastCommandFrom);
    uintField(body, 8, lastCommandId);
  }
  if (active && activeSince) uintField(body, 9, activeSince);
  uintField(body, 12, timeMs);                   // client_side_timestamp

  const int status = engine.putConnectState(connectionId, body);
  if (status != 200)
    nxlog::pushf("Connect: state push (reason %d) answered HTTP %d", reason, status);
  else if (reason == NewDevice)
    nxlog::push("Connect: this device is listed now");
  (void)BecameInactive;
}

}  // namespace switify::phase2
