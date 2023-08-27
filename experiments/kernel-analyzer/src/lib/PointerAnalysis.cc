#include<llvm/IR/Instructions.h>
#include<llvm/IR/Function.h>
#include<llvm/IR/InstIterator.h>
#include<llvm/IR/LegacyPassManager.h>
#include <llvm/Analysis/AliasAnalysis.h>

#include "PointerAnalysis.h"

bool PointerAnalysisPass::doInitialization(Module *M) {
    return false;
}

bool PointerAnalysisPass::doFinalization(Module *M) {
    return false;
}

void* PointerAnalysisPass::getSourcePointer(Value *P) {
    Value *SrcP = P;
    Instruction *SrcI = dyn_cast<Instruction>(SrcP);

    std::list<Value *> EI;

    EI.push_back(SrcP);
    while (!EI.empty()) {
        Value *TI = EI.front();
        EI.pop_front();

        // Possible sources
        if (isa<Argument>(TI)
                || isa<AllocaInst>(TI)
                || isa<CallInst>(TI)
                || isa<GlobalVariable>(TI)
           )
            return SrcP;

        if (UnaryInstruction *UI = dyn_cast<UnaryInstruction>(TI)) {
            Value *UO = UI->getOperand(0);
            if (UO->getType()->isPointerTy() && isa<Instruction>(UO)) {
                SrcP = UO;
                EI.push_back(SrcP);
            }
        }
        else if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(TI)) {
            SrcP = GEP->getPointerOperand();
            EI.push_back(SrcP);
            // break;
        }
    }

    return SrcP;
}

static void addToSet(std::set<Value *> &addrSet, Value *addr){
    if(addrSet.find(addr) == addrSet.end())
        addrSet.insert(addr);
}

void PointerAnalysisPass::detectAliasPointers(Function* F, AAResults &AAR, 
        PointerAnalysisMap &aliasPtrs) {

    std::set<Value *> addr1Set;
    std::set<Value *> addr2Set;
    Value *Addr1, *Addr2;

    /*
    for (inst_iterator i = inst_begin(F), ei = inst_end(F);
         i != ei; ++i) {

         Instruction *I = dyn_cast<Instruction>(&*i);
        
         if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
             addToSet(addr1Set, LI->getPointerOperand());
         } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
             addToSet(addr1Set, SI->getPointerOperand());
         } else if (CallInst *CI = dyn_cast<CallInst>(I)) {
             for (unsigned j = 0, ej = CI->getNumArgOperands();
                     j < ej; ++j) {
                 Value *Arg = CI->getArgOperand(j);

                 if (!Arg->getType()->isPointerTy())
                     continue;
                 addToSet(addr1Set, Arg);
             }
         }
     }
     */

    // this runs really slow
    // for (Argument &A : F->args())
    //     if (A.getType()->isPointerTy())
    //         addr1Set.insert(&A);

    // for (Instruction &I : instructions(*F))
    //     if (I.getType()->isPointerTy())
    //         addr1Set.insert(&I);

    // if (addr1Set.size() > 1000) {
    //     return;
    // }

    for (auto Addr1 : addr1Set) {
        for (auto Addr2 : addr1Set) {
            if (Addr1 == Addr2)
                continue;
            AliasResult AResult = AAR.alias(Addr1, Addr2);

            bool notAlias = true;

            if (AResult == MustAlias || AResult == PartialAlias) {
                notAlias = false;
            } else if (AResult == MayAlias) {
                // FIXME: 
                // if (getSourcePointer(Addr1) == getSourcePointer(Addr2))
                //     notAlias = false;
            } 

            if (notAlias)
                continue;

            auto as = aliasPtrs.find(Addr1);
            if (as == aliasPtrs.end()) {
                SmallPtrSet<Value *, 16> sv;
                sv.insert(Addr2);
                aliasPtrs[Addr1] = sv;
            } else {
                as->second.insert(Addr2);
            }
        }
    }
}

bool PointerAnalysisPass::doModulePass(Module *M) {

    legacy::FunctionPassManager *FPasses = new legacy::FunctionPassManager(M);
    AAResultsWrapperPass *AARPass = new AAResultsWrapperPass();

    FPasses->add(AARPass);

    FPasses->doInitialization();

    for (Function &F : *M) {
        if (F.isDeclaration())
            continue;
        FPasses->run(F);
    }
    FPasses->doFinalization();

    AAResults &AAR = AARPass->getAAResults();

    for (Module::iterator f = M->begin(), fe = M->end();
            f != fe; ++f) {

        Function* F = &*f;
        PointerAnalysisMap aliasPtrs;

        if (F->empty())
            continue;
        detectAliasPointers(F, AAR, aliasPtrs);
        
        Ctx->FuncPAResults[F] = aliasPtrs;
        Ctx->FuncAAResults[F] = &AAR;
    }

    return false;
}

