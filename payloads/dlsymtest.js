(async function() {

    libSceGnmDriver = load_prx("/system/common/lib/libSceGnmDriver.sprx");
    
    await log("libSceGnmDriver handle : " + toHex(libSceGnmDriver));
    
    sceGnmSubmitCommandBuffers = dlsym(libSceGnmDriver, "sceGnmSubmitCommandBuffers");
    
    await log("sceGnmSubmitCommandBuffers : " + toHex(sceGnmSubmitCommandBuffers));
    
})();