#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>

#include "PermissionAnalysis.h"

bool PermissionAnalysisPass::doInitialization(Module *M) {

    for (Module::global_iterator gi = M->global_begin(); 
			gi != M->global_end(); ++gi) {
		GlobalVariable* GV = &*gi;
		if (!GV->hasInitializer())
			continue;
		Constant *Ini = GV->getInitializer();
		if (!isa<ConstantAggregate>(Ini))
			continue;

		checkDevicePermission(Ini);
	}

    return false;
}

// return true if the operation is priviledged.
bool PermissionAnalysisPass::checkPermission(CallInst *CI, int offset) {
    Value *v = CI->getOperand(offset);
    if (auto *m = dyn_cast<ConstantInt>(v)) {
        int mode = m->getZExtValue();
        if (mode % 8 == 0 && mode % 64 == 0) {
            return true;
        }
    }
    return false;
}

bool PermissionAnalysisPass::checkDevicePermission(User *Ini) {

	list<User *>LU;
	LU.push_back(Ini);

	while (!LU.empty()) {
		User *U = LU.front();
		LU.pop_front();

		bool deny = false;
        bool dev = false;
        if (auto *ST = dyn_cast<StructType>(U->getType())) {
            if (ST->getName().find("struct.cdevsw") == 0) {
                for (auto *user : U->users()) {
                    for (auto *uu : user->users()) {
                        if (CallInst *CI = dyn_cast<CallInst>(uu)) {
                            Function *F = CI->getCalledFunction();
                            if (F && F->getName() == "make_dev") {
                                dev = true;
                                deny |= checkPermission(CI, 4);
                            } else if (F && F->getName().find("make_dev") == 0) {
                                // log out others
                                outs() << "Please handle this function: " << F->getName() << "\n";
                            }
                        }
                    }
                }
            }
		}

        if (!dev) {
            continue;
        }

		for (auto oi = U->op_begin(), oe = U->op_end(); 
				    oi != oe; ++oi) {
            Value *O = *oi;
            Type *OTy = O->getType();
            
            if (Function *F = dyn_cast<Function>(O)) {
                if (!deny) {
                    // add to allow list
                    outs() << "adding "<<F->getName()<<" to allow list\n";
                    Ctx->devAllowList.insert(F);
                } else {
                    // add to deny list
                    outs() << "adding "<<F->getName()<<" to deny list\n";
                    Ctx->devDenyList.insert(F);
                }
            }
        }
    }

	return true;
}



bool PermissionAnalysisPass::doFinalization(Module *M) {
    return false;
}

bool PermissionAnalysisPass::doModulePass(Module *M) {
    return false;
}