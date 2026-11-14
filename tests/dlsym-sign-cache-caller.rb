# The actual dlsym signing function with controlled collaborators: an arm64e caller that lives in the split cache (which
# findImageContainingAddress does not know) must be handed a signed pointer; a plain disk image or an unknown address must not.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0))
source=File.read("#{root}/src/dyldAPIs.cpp")
if ENV['DLSYM_SOURCE_REF']
  source,ok=Open3.capture2('git','-C',root,'show',"#{ENV.fetch('DLSYM_SOURCE_REF')}:src/dyldAPIs.cpp")
  abort 'source unavailable' unless ok.success?
end
fn=source[/static void\* darlingDlsymSignForCaller\(.*?^\t\}/m] or abort 'darlingDlsymSignForCaller missing'
Dir.mktmpdir('dlsym-sign-cache-caller-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <stdio.h>
    #include <string.h>
    struct mach_header { int cpusubtype; };
    struct ImageLoader { mach_header mh; const mach_header* machHeader() const { return &mh; } };
    struct DyldSharedCache { uint64_t size; uint64_t mappedSize() const { return size; } };
    static ImageLoader gArm64e = { { 2 } };
    static ImageLoader gPlain = { { 1 } };
    static char gDiskArm64e[16], gDiskPlain[16];
    alignas(16) static char gCacheStorage[4096];
    static DyldSharedCache* gCache = nullptr;
    namespace dyld {
      ImageLoader* findImageContainingAddress(const void* a) {
        if ( a == gDiskArm64e ) return &gArm64e;
        if ( a == gDiskPlain ) return &gPlain;
        return nullptr;   // the split cache's addresses are not in the mapped ranges
      }
      const void* imMemorySharedCacheHeader() { return gCache; }
    }
    namespace dyld3 { namespace darling {
      bool cpusubtypeIsArm64e(int s) { return s == 2; }
      uint64_t adaptedTarget(const char*, uint64_t t, bool) { return t; }
    }}
    #define DARLING_DLSYM_SIGN(p) ((void*)((uint64_t)(p) | (1ULL << 53)))
    #{fn}
    static int check(const char* what, void* caller, bool expectSigned) {
      void* r = darlingDlsymSignForCaller((void*)0x1000, caller, "_f");
      bool isSigned = ((uint64_t)r >> 48) != 0;
      printf("%s: %s\\n", what, isSigned == expectSigned ? "ok" : "WRONG");
      return isSigned == expectSigned ? 0 : 1;
    }
    int main() {
      int bad = 0;
      // the cache object is the header at the start of the mapped region: use the storage as the region
      gCache = (DyldSharedCache*)gCacheStorage; gCache->size = sizeof(gCacheStorage);
      bad += check("caller in an arm64e disk image", gDiskArm64e, true);
      bad += check("caller in a plain disk image", gDiskPlain, false);
      bad += check("caller inside the split cache", gCacheStorage + 100, true);
      bad += check("caller outside every image and the cache", (void*)0x10, false);
      gCache = nullptr;
      bad += check("caller unknown, no cache", gCacheStorage + 100, false);
      return bad;
    }
  CPP
  out,st=Open3.capture2e('c++','-std=c++17','-o',"#{dir}/test","#{dir}/test.cpp")
  abort out unless st.success?
  out,st=Open3.capture2e("#{dir}/test")
  puts out
  abort 'dlsym signing check failed' unless st.success?
end
