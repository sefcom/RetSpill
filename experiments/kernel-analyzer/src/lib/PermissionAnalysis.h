#ifndef PERMISSION_ANALYZER_H
#define PERMISSION_ANALYZER_H

#include "GlobalCtx.h"
#include "Common.h"

using namespace llvm;

class PermissionAnalysisPass : public IterativeModulePass {

private:
    bool checkDevicePermission(User *Ini);
    bool checkPermission(CallInst *CI, int offset);
public:

    PermissionAnalysisPass(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "PermissionAnalysisPass") {}
    virtual bool doInitialization(Module*);
    virtual bool doFinalization(Module*);
    virtual bool doModulePass(Module*);
};

#endif
