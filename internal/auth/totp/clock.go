package totp

import "time"

// timeNow indirects time.Now so tests can pin the wall clock and exercise
// step boundaries deterministically.
var timeNow = time.Now
