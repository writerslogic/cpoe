// Licensed under the GNU Affero General Public License v3.0 with Commercial dual-licensing
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use shared::minwindef::{BOOL, PULONG, PUSHORT, ULONG, USHORT};
use um::winnt::PGROUP_AFFINITY;
extern "system" {
    pub fn GetNumaHighestNodeNumber(
        HighestNodeNumber: PULONG,
    ) -> BOOL;
    pub fn GetNumaNodeProcessorMaskEx(
        Node: USHORT,
        ProcessorMask: PGROUP_AFFINITY,
    ) -> BOOL;
    pub fn GetNumaProximityNodeEx(
        ProximityId: ULONG,
        NodeNumber: PUSHORT,
    ) -> BOOL;
}
