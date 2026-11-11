#include "game_volume.hpp"

#include "NXConsoleLog.h"

#include <switch.h>

#include <algorithm>
#include <atomic>

namespace switify::phase2::game_volume {
namespace {

std::atomic<uint32_t> wanted{1000};
uint32_t applied = 1000;   // what the game last got
uint64_t appliedPid = 0;
uint64_t lastTick = 0;
bool audaOpen = false;
bool audaFailed = false;
bool pmOpen = false;

}  // namespace

void set(uint32_t permille) { wanted.store(std::min<uint32_t>(permille, 1000)); }

uint32_t get() { return wanted.load(); }

bool apply() {
  const uint64_t now = armGetSystemTick();
  if (now - lastTick < armNsToTicks(100'000'000ULL)) return true;
  lastTick = now;
  const uint32_t value = wanted.load();
  // At 100 % nothing is held: the game's volume was given back once, and the
  // system's own changes are left alone.
  if (value == 1000 && applied == 1000) return true;
  if (!audaOpen) {
    if (audaFailed) return false;
    if (hosversionBefore(11, 0, 0)) {
      audaFailed = true;
      nxlog::push("Game volume: needs firmware 11.0.0 or newer");
      return false;
    }
    const Result rc = audaInitialize();
    if (R_FAILED(rc)) {
      audaFailed = true;
      nxlog::pushf("Game volume: aud:a refused (0x%X)", static_cast<unsigned>(rc));
      return false;
    }
    audaOpen = true;
    nxlog::push("Game volume: aud:a open");
  }
  if (!pmOpen) {
    if (R_FAILED(pmdmntInitialize())) return false;
    pmOpen = true;
  }
  u64 pid = 0;
  if (R_FAILED(pmdmntGetApplicationProcessId(&pid)) || pid == 0) {
    appliedPid = 0;  // no game: the next one gets it when it starts
    return true;
  }
  const float volume = static_cast<float>(value) / 1000.f;
  const Result rc = audaSetAudioOutputProcessMasterVolume(pid, 0, volume);
  if (R_FAILED(rc)) {
    if (pid != appliedPid) nxlog::pushf("Game volume: refused for the game (0x%X)", static_cast<unsigned>(rc));
    appliedPid = pid;
    return false;
  }
  if (pid != appliedPid || value != applied)
    nxlog::pushf("Game volume: %u%% for the game", static_cast<unsigned>(value / 10));
  appliedPid = pid;
  applied = value;
  if (value == 1000) {  // given back: let go of the sessions too
    audaExit();
    audaOpen = false;
    pmdmntExit();
    pmOpen = false;
  }
  return true;
}

}  // namespace switify::phase2::game_volume
