#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class SpotifyEngine;

// Spotify Connect as current Spotify apps see it: the dealer websocket and
// connect-state (cspot only speaks the older SPIRC, which phones no longer
// list). The device shows up in the phone's Connect picker, and the phone's
// transfer / play / pause / seek / skip / volume reach the engine.
//
// Ported from go-librespot (github.com/devgianlu/go-librespot, GPL-3.0):
// dealer/dealer.go, dealer/recv.go, daemon/player_state.go, controls.go.
//
// Never blocks: the background service has two BSD sessions and the access
// point's reader holds one all the time, so the socket is non-blocking and
// tick() (the backend's loop, every 50 ms) does a little at a time.
namespace switify::phase2 {

class ConnectDealer {
 public:
  explicit ConnectDealer(SpotifyEngine& engine);
  ~ConnectDealer();

  void tick();
  // The engine's state changed (a song, pause, seek): pushed when active.
  void playerChanged();

 private:
  struct Tls;
  enum class Phase { Idle, Handshake, Upgrade, Open };

  bool connect();
  void close(const char* why);
  bool stepHandshake();
  bool stepUpgrade();
  bool stepOpen();
  bool readSome();
  bool sendFrame(uint8_t opcode, const std::string& payload);
  bool writeAll(const uint8_t* data, size_t size);
  void handleText(const std::string& text);
  void handleMessage(const std::string& uri, const std::string& payload,
                     bool gzip, const std::string& connectionId);
  bool handleCommand(const std::string& json);
  void reply(const std::string& key, bool success);
  void pushState(int reason);

  SpotifyEngine& engine;
  std::unique_ptr<Tls> tls;
  Phase phase = Phase::Idle;
  std::string rx;             // bytes read, not yet a whole frame
  std::string fragments;      // a message in continuation frames
  std::string connectionId;
  std::string deviceId;
  std::chrono::steady_clock::time_point retryAt{};
  std::chrono::steady_clock::time_point lastPing{}, lastPong{}, upgradeSent{};
  std::chrono::seconds backoff{5};
  bool active = false;        // the account's active device is this one
  bool dirty = false;         // a state push is due
  std::chrono::steady_clock::time_point lastPush{};
  uint64_t activeSince = 0;
  uint32_t lastCommandId = 0;
  std::string lastCommandFrom;
  std::string contextUri;
  std::string sessionId, playbackId;
  std::string lastSeen;       // the player as last pushed (uri, paused, options)
};

}  // namespace switify::phase2
