#pragma once

#include <cstdint>

// The running game's own volume (the overlay's "Game volume" slider), so the
// game can be turned down under the music. As sys-tune does it: aud:a's
// process master volume for the application's process, set again and again
// (a game that opens its audio after the change would not have it).
namespace switify::phase2::game_volume {

void set(uint32_t permille);  // 0..1000; 1000 is the game as it is
uint32_t get();
// From the backend's loop: applies it (at most every 100 ms). Returns false
// when the system refused (aud:a busy, no game running is not a failure).
bool apply();

}  // namespace switify::phase2::game_volume
