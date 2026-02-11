// Licensed under the GNU Affero General Public License v3.0 with Commercial dual-licensing
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
//! This file contains information about NetApiBuffer APIs
use shared::lmcons::NET_API_STATUS;
use shared::minwindef::{DWORD, LPDWORD, LPVOID};
extern "system" {
    pub fn NetApiBufferAllocate(
        ByteCount: DWORD,
        Buffer: *mut LPVOID,
    ) -> NET_API_STATUS;
    pub fn NetApiBufferFree(
        Buffer: LPVOID,
    ) -> NET_API_STATUS;
    pub fn NetApiBufferReallocate(
        OldBuffer: LPVOID,
        NewByteCount: DWORD,
        NewBuffer: *mut LPVOID,
    ) -> NET_API_STATUS;
    pub fn NetApiBufferSize(
        Buffer: LPVOID,
        ByteCount: LPDWORD,
    ) -> NET_API_STATUS;
    pub fn NetapipBufferAllocate(
        ByteCount: DWORD,
        Buffer: *mut LPVOID,
    ) -> NET_API_STATUS;
}
