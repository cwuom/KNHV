#include "nested_internal.h"

namespace knhv {
namespace nested_internal {

bool TranslateLinear(const NestedMemory& memory, u64 linear, u32 access,
                     u64* guest_physical) {
    if (guest_physical == nullptr || memory.translate == nullptr) return false;
    return memory.translate(memory.context, linear, guest_physical, access);
}

bool ReadLinear(const NestedMemory& memory, u64 linear, void* buffer,
                u32 length, u32 access) {
    if (buffer == nullptr || length == 0 || memory.read == nullptr ||
        memory.translate == nullptr) {
        return false;
    }
    u8* destination = static_cast<u8*>(buffer);
    u32 remaining = length;
    u64 current = linear;
    while (remaining != 0) {
        u64 guest_physical = 0;
        if (!TranslateLinear(memory, current, access, &guest_physical)) {
            return false;
        }
        // split at the linear page boundary because a guest mapping may
        // translate adjacent linear pages to non-adjacent physical pages
        const u32 page_offset = static_cast<u32>(
            current & (static_cast<u64>(kNestedPageSize) - 1ULL));
        const u32 chunk = (remaining < kNestedPageSize - page_offset)
                              ? remaining
                              : kNestedPageSize - page_offset;
        if (chunk == 0 || !memory.read(memory.context, guest_physical,
                                       destination, chunk)) {
            return false;
        }
        destination += chunk;
        remaining -= chunk;
        if (remaining != 0) {
            if (current > ~static_cast<u64>(0) - chunk) return false;
            current += chunk;
        }
    }
    return true;
}

bool WriteLinear(const NestedMemory& memory, u64 linear, const void* buffer,
                 u32 length) {
    if (buffer == nullptr || length == 0 || memory.write == nullptr ||
        memory.translate == nullptr) {
        return false;
    }
    const u8* source = static_cast<const u8*>(buffer);
    u32 remaining = length;
    u64 current = linear;
    while (remaining != 0) {
        u64 guest_physical = 0;
        if (!TranslateLinear(
                memory, current,
                static_cast<u32>(NestedMemoryAccess::Write),
                &guest_physical)) {
            return false;
        }
        // split at the linear page boundary because a guest mapping may
        // translate adjacent linear pages to non-adjacent physical pages
        const u32 page_offset = static_cast<u32>(
            current & (static_cast<u64>(kNestedPageSize) - 1ULL));
        const u32 chunk = (remaining < kNestedPageSize - page_offset)
                              ? remaining
                              : kNestedPageSize - page_offset;
        if (chunk == 0 || !memory.write(memory.context, guest_physical, source,
                                        chunk)) {
            return false;
        }
        source += chunk;
        remaining -= chunk;
        if (remaining != 0) {
            if (current > ~static_cast<u64>(0) - chunk) return false;
            current += chunk;
        }
    }
    return true;
}

}  // namespace nested_internal
}  // namespace knhv
