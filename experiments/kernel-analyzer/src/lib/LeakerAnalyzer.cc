/*
 * Copyright (C) 2019 Yueqi (Lewis) Chen, Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/TypeFinder.h>
#include <llvm/Pass.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/raw_ostream.h>

#include "Annotation.h"
#include "LeakerAnalyzer.h"

using namespace llvm;
using namespace std;

extern cl::opt<bool> IgnoreReachable;

// initialize moduleStructMap
bool LeakerAnalyzerPass::doInitialization(Module *M) {

  StructTypeSet structTypeSet;
  TypeFinder usedStructTypes;
  usedStructTypes.run(*M, false);

  for (TypeFinder::iterator itr = usedStructTypes.begin(),
                            ite = usedStructTypes.end();
       itr != ite; itr++) {

    StructType *st = *itr;
    // only deal with non-opaque type
    if (st->isOpaque())
      continue;

    structTypeSet.insert(st);
  }

  Ctx->moduleStructMap.insert(std::make_pair(M, structTypeSet));

  if (Ctx->LeakAPIs.size() == 0) {
    composeMbufLeakAPI();
  }

  return false;
}

// determine "allocable" and "leakable" to compute allocInstMap and leakInstMap
bool LeakerAnalyzerPass::doModulePass(Module *M) {

  ModuleStructMap::iterator it = Ctx->moduleStructMap.find(M);
  assert(it != Ctx->moduleStructMap.end() &&
         "M is not analyzed in doInitialization");

  // no flexible structure usage in this module
  // TODO Lewis: is this a golden rule?
  // Counter example: leak in M1, struct info in M2 and pass to M1
  if (it->second.size() == 0)
    return false;

  for (Function &F : *M)
    runOnFunction(&F);

  return false;
}

// check if the function is called by a priviledged device
// return true if the function is priviledged.
bool LeakerAnalyzerPass::isPriviledged(llvm::Function *F) { return false; }

// start analysis from calling to allocation or leak functions
void LeakerAnalyzerPass::runOnFunction(Function *F) {
  if (!IgnoreReachable) {
    FuncSet Syscalls = reachableSyscall(F);
    if (Syscalls.size() == 0) {
      return;
    }
    KA_LOGS(1, F->getName() << " can be reached by " << Syscalls.size()
                            << " syscalls\n");
  }

  // skip functions in .init.text which is used only during booting
  if (F->hasSection() && F->getSection().str() == ".init.text")
    return;

  for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
    Instruction *I = &*i;
    if (CallInst *callInst = dyn_cast<CallInst>(I)) {
      const Function *callee = callInst->getCalledFunction();
      if (!callee)
        callee =
            dyn_cast<Function>(callInst->getCalledValue()->stripPointerCasts());
      if (callee) {
        std::string calleeName = callee->getName().str();
        if (isCopyIn(calleeName)) {
          analyzeCopyIn(callInst, calleeName);
        }
      }
    }
  }
  return;
}

bool LeakerAnalyzerPass::isCall2Alloc(std::string calleeName) {
  if (std::find(allocAPIVec.begin(), allocAPIVec.end(), calleeName) !=
      allocAPIVec.end())
    return true;
  else if (calleeName.find("alloc") != std::string::npos ||
           calleeName.find("ALLOC") != std::string::npos)
    // aggressive analysis
    return true;
  return false;
}

bool LeakerAnalyzerPass::isCall2Leak(std::string calleeName) {
  if (std::find(leakAPIVec.begin(), leakAPIVec.end(), calleeName) !=
      leakAPIVec.end())
    return true;
#if 0
    else if (calleeName.find("memcpy") != string::npos)
        return true;
#endif
  else
    return false;
}

bool LeakerAnalyzerPass::isCopyIn(std::string calleeName) {
  if (std::find(copyInAPIVec.begin(), copyInAPIVec.end(), calleeName) !=
      copyInAPIVec.end())
    return true;
  return false;
}

void LeakerAnalyzerPass::backwardUseAnalysis(
    llvm::Value *V, std::set<llvm::Value *> &DefineSet) {
  // TODO: handle reg2mem store load pair
  if (auto *I = dyn_cast<Instruction>(V)) {
    KA_LOGS(2, "backward handling " << *I << "\n");
    if (I->isBinaryOp() || dyn_cast<ICmpInst>(I)) {
      KA_LOGS(2, *I << " backward Adding " << *V << "\n");
      DefineSet.insert(V);

      for (unsigned i = 0, e = I->getNumOperands(); i != e; i++) {
        Value *Opd = I->getOperand(i);
        KA_LOGS(2, "backward Adding " << *V << "\n");
        DefineSet.insert(V);
        if (dyn_cast<ConstantInt>(Opd))
          continue;
        backwardUseAnalysis(Opd, DefineSet);
      }

    } else if (dyn_cast<CallInst>(I) || dyn_cast<SelectInst>(I)) {
      KA_LOGS(2, "backward Adding " << *V << "\n");
      DefineSet.insert(V);
    } else if (auto *PN = dyn_cast<PHINode>(I)) {

      if (DefineSet.find(V) != DefineSet.end())
        return;

      KA_LOGS(2, "backward Adding " << *V << "\n");
      DefineSet.insert(V);
      // aggressive analysis
      for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; i++) {
        Value *IV = PN->getIncomingValue(i);
        if (dyn_cast<ConstantInt>(IV))
          continue;
        backwardUseAnalysis(IV, DefineSet);
      }

    } else if (UnaryInstruction *UI = dyn_cast<UnaryInstruction>(V)) {
      KA_LOGS(2, "backward Adding " << *V << "\n");
      DefineSet.insert(V);

      backwardUseAnalysis(UI->getOperand(0), DefineSet);
    } else if (auto *GEP = dyn_cast<GetElementPtrInst>(I)) {
      // may come from the same struct
      KA_LOGS(2, "backward Adding " << *V << "\n");
      DefineSet.insert(V);

      backwardUseAnalysis(GEP->getOperand(0), DefineSet);
    } else {
      errs() << "Backward Fatal errors , please handle " << *I << "\n";
      // exit(0);
    }
  } else {
    // argument
    KA_LOGS(2, "Backward Adding " << *V << "\n");
    DefineSet.insert(V);
  }
}

llvm::Value *LeakerAnalyzerPass::getOffset(llvm::GetElementPtrInst *GEP) {
  // FIXME: consider using more sophisicated method
  // Use the last indice of GEP
  return GEP->getOperand(GEP->getNumIndices());
}

void LeakerAnalyzerPass::forwardAnalysis(
    llvm::Value *V, std::set<llvm::StoreInst *> &StoreInstSet,
    std::set<llvm::Value *> &TrackSet) {

  for (auto *User : V->users()) {

    if (TrackSet.find(User) != TrackSet.end())
      continue;

    TrackSet.insert(User);

    KA_LOGS(2, "Forward " << *User << "\n");

    // FIXME: should we check if V is SI's pointer?
    if (StoreInst *SI = dyn_cast<StoreInst>(User)) {
      StoreInstSet.insert(SI);

      // forward memory alias
      Value *SV = SI->getValueOperand();
      Value *SP = SI->getPointerOperand();

      for (auto *StoreU : SP->users()) {
        // alias pair
        if (dyn_cast<LoadInst>(StoreU)) {
          KA_LOGS(2, "Found Store and Load pair " << *StoreU << " " << *User
                                                  << "\n");
          forwardAnalysis(StoreU, StoreInstSet, TrackSet);
        }
      }

      // handle struct alias
      if (auto *GEP = dyn_cast<GetElementPtrInst>(SP)) {
        Value *red_offset = getOffset(GEP);
        Value *red_obj = GEP->getOperand(0);

        KA_LOGS(2, "Marking " << *red_obj << " as red\n");

        for (auto *ObjU : red_obj->users()) {
          if (auto *ObjGEP = dyn_cast<GetElementPtrInst>(ObjU)) {

            if (ObjGEP != GEP && getOffset(ObjGEP) == red_offset) {
              // we found it
              // and then check if its user is LOAD.
              for (auto *OGEPUser : ObjGEP->users()) {
                if (dyn_cast<LoadInst>(OGEPUser)) {
                  KA_LOGS(2, "Solved Alias : " << *OGEPUser << " == " << *User
                                               << "\n");
                  forwardAnalysis(OGEPUser, StoreInstSet, TrackSet);
                }
              }
            }
          }
        }
        // should we forward sturct ?
      }
    } else if (dyn_cast<GetElementPtrInst>(User) || dyn_cast<ICmpInst>(User) ||
               dyn_cast<BranchInst>(User) || dyn_cast<BinaryOperator>(User)) {

      forwardAnalysis(User, StoreInstSet, TrackSet);

    } else if (dyn_cast<CallInst>(User) || dyn_cast<CallBrInst>(User) ||
               dyn_cast<SwitchInst>(User) || dyn_cast<ReturnInst>(User)) {

      continue;

      // } else if(dyn_cast<UnaryInstruction>(User)){
    } else if (dyn_cast<SExtInst>(User) || dyn_cast<ZExtInst>(User) ||
               dyn_cast<TruncInst>(User)) {

      forwardAnalysis(User, StoreInstSet, TrackSet);

    } else if (dyn_cast<PHINode>(User) || dyn_cast<SelectInst>(User) ||
               dyn_cast<LoadInst>(User) || dyn_cast<UnaryInstruction>(User)) {

      // TODO: forward PHI node
      forwardAnalysis(User, StoreInstSet, TrackSet);

    } else {
      errs() << "\nForwardAnalysis Fatal errors , please handle " << *User
             << "\n";
      // exit(0);
    }
  }
}

// customize flexible part here
// every time adding a new struct to allocInstMap,
// update allocSyscallMap
void LeakerAnalyzerPass::analyzeAlloc(llvm::CallInst *callInst) {

  StructType *stType;
  Function *F;
  Module *M;
  BitCastInst *BCI;
  std::set<Value *> dynArgSet;

  M = callInst->getModule();
  F = callInst->getCalledFunction();

  if (callInst->getNumArgOperands() == 0)
    return;

  Value *add = callInst->getArgOperand(0);

  if (!isa<Instruction>(add)) {
    return;
  }

  if (!isa<BinaryOperator>(add)) {
    return;
  }

  // get the flexible size
  BinaryOperator *BO = dyn_cast<BinaryOperator>(add);
  for (int i = 0; i < BO->getNumOperands(); i++) {
    if (!dyn_cast<Constant>(BO->getOperand(i))) {
      dynArgSet.insert(BO->getOperand(i));
    }
  }

  if (!F) {
    if (Function *FF = dyn_cast<Function>(
            callInst->getCalledValue()->stripPointerCasts())) {
      F = FF;
    }
  }

  if (F) {
    Type *baseType = F->getReturnType();
    stType = dyn_cast<StructType>(baseType);
  }

  if (!stType) {
    for (auto *callUser : callInst->users()) {
      if (isa<BitCastInst>(callUser)) {
        BCI = dyn_cast<BitCastInst>(callUser);
        PointerType *ptrType = dyn_cast<PointerType>(BCI->getDestTy());
        Type *baseType = ptrType->getElementType();
        stType = dyn_cast<StructType>(baseType);
        if (stType == nullptr)
          continue;
        break;
      }
    }
  }

  if (!stType)
    return;

  // check if the flexible size is stored
  for (auto *dynArg : dynArgSet) {
    for (auto *dynArgUser : dynArg->users()) {
      // let's skip UnaryInst
      Value *current = dynArgUser;
      if (auto *UI = dyn_cast<UnaryInstruction>(current)) {
        if (UI->getNumUses() != 1) {
          continue;
        }

        for (auto *xx : UI->users()) {
          current = xx;
          break;
        }
      }

      if (isa<StoreInst>(current)) {
        auto *SI = dyn_cast<StoreInst>(current);
        if (auto *GEP = dyn_cast<GetElementPtrInst>(SI->getOperand(1))) {
          Value *src = GEP->getOperand(0);
          if (src && (src == callInst || src == BCI)) {
            // we found
            auto *offset = dyn_cast<ConstantInt>(GEP->getOperand(2));
            StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

            assert(stInfo != NULL);

            stInfo->hasBoundary = true;
            stInfo->boundaryOffset = offset->getZExtValue();
            // allocation information
            stInfo->allocaInst.insert(callInst);
          }
        }
      }
    }
  }

  /*
  // compose allocInst map
  string structName = getScopeName(stType, M);


  KA_LOGS(1, "We found " << structName << "\n");
  if (structName.find("struct") == string::npos)
      return;

  Function *body = callInst->getFunction();

  LeakStructMap::iterator it = Ctx->leakStructMap.find(structName);
  if (it != Ctx->leakStructMap.end()) {

      it->second->allocaInst.insert(callInst);

  } else {
      StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);
      if (!stInfo) return;
      stInfo->allocaInst.insert(callInst);
      Ctx->leakStructMap.insert(std::make_pair(structName, stInfo));
  }
  */
}

static bool argContainType(Function *F, string typeName) {
  for (auto arg = F->arg_begin(); arg != F->arg_end(); ++arg) {
    PointerType *ptrType = dyn_cast<PointerType>(arg->getType());
    if (ptrType == nullptr)
      continue;

    Type *baseType = ptrType->getElementType();
    StructType *stType = dyn_cast<StructType>(baseType);
    if (stType == nullptr)
      continue;

    if (stType->getName() == typeName)
      return true;
  }
  return false;
}

static bool argContainMbuf(Function *F) {
  return argContainType(F, "struct.mbuf");
}

static bool addToFuncSet(Function *F, FuncSet &markedFuncSet) {
  if (F && markedFuncSet.find(F) == markedFuncSet.end()) {
    markedFuncSet.insert(F);
    return true;
  }
  return false;
}

static bool addToCallInstSet(CallInst *CI, CallInstSet &CISet) {
  if (CI && CISet.find(CI) == CISet.end()) {
    CISet.insert(CI);
    return true;
  }
  return false;
}

static bool isSndbuf(Value *V) {
  if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
    PointerType *ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
    if (!ptrType)
      return false;

    Type *baseType = ptrType->getElementType();
    StructType *stType = dyn_cast<StructType>(baseType);

    if (stType->getName() != "struct.socket")
      return false;

    if (GEP->getNumIndices() != 2)
      return false;

    if (auto *offset1 = dyn_cast<ConstantInt>(GEP->getOperand(1))) {
      if (auto *offset2 = dyn_cast<ConstantInt>(GEP->getOperand(2))) {
        if (offset1->getZExtValue() == 0 && offset2->getZExtValue() == 19) {
          return true;
        }
      }
    }
  }
  return false;
}

bool LeakerAnalyzerPass::isMbufData(Value *buf) {
  std::vector<Value *> srcBufSet;
  std::set<Value *> trackedBufSet;
  findSources(buf, srcBufSet, trackedBufSet);

  for (std::vector<llvm::Value *>::iterator i = srcBufSet.begin(),
                                            e = srcBufSet.end();
       i != e; i++) {
    Value *V = *i;
    if (auto *callInst = dyn_cast<CallInst>(V)) {

    } else if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
      if (GEP->getNumIndices() == 1)
        continue;

      PointerType *ptrType =
          dyn_cast<PointerType>(GEP->getPointerOperandType());
      if (ptrType == nullptr)
        continue;
      Type *baseType = ptrType->getElementType();
      StructType *stType = dyn_cast<StructType>(baseType);
      if (stType == nullptr)
        continue;
      ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
      if (CI->getZExtValue() != 2)
        continue;

      if (stType->getName() == "struct.mbuf") {
        return true;
      }
    }
  }
  return false;
}

void LeakerAnalyzerPass::composeMbufLeakAPI() {

  CallInstSet LeakInst;
  FuncSet trackedFuncSet;

  for (auto M : Ctx->Callers) {
    Function *F = M.first;

    if (!addToFuncSet(F, trackedFuncSet))
      continue;

    if (!argContainMbuf(F))
      continue;

    if (argContainType(F, "struct.sockbuf")) {
      // if the sockbuf is coming from sock's snd_buf
      CallerMap::iterator it = Ctx->Callers.find(F);
      if (it == Ctx->Callers.end()) {
        continue;
      }
      CallInstSet &CIS = it->second;

      for (CallInst *CI : CIS) {
        // check if sockbuf is snd_buf
        for (unsigned i = 0; i < CI->getNumArgOperands(); i++) {
          if (isSndbuf(CI->getArgOperand(i))) {
            addToCallInstSet(CI, LeakInst);
            KA_LOGS(1, "LEAK API: " << CI->getFunction()->getName()
                                    << " --------\n");
            KA_LOGS(1, "CallInst : ");
            DEBUG_Inst(1, CI);
            KA_LOGS(1, "\n");
          }
        }
      }
    }
  }

  SmallVector<Function *, 4> workList;

  workList.clear();

  for (auto *CI : LeakInst) {
    Function *F = CI->getFunction();
    if (!F)
      continue;
    workList.push_back(F);
  }

  trackedFuncSet.clear();

  while (!workList.empty()) {
    Function *FF = workList.pop_back_val();

    // already checked FF
    if (!addToFuncSet(FF, trackedFuncSet))
      continue;

    // add before checking mbuf in argument
    // so as to include top APIs that don't
    // have mbuf in arguments.
    addToFuncSet(FF, Ctx->LeakAPIs);

    if (!argContainMbuf(FF))
      continue;

    CallerMap::iterator it = Ctx->Callers.find(FF);
    if (it == Ctx->Callers.end()) {
      continue;
    }
    CallInstSet &CIS = it->second;

    for (CallInst *CI : CIS) {
      Function *CallerF = CI->getParent()->getParent();
      workList.push_back(CallerF);
    }
  }

  FuncSet tmpFuncSet;
  for (auto *FF : Ctx->LeakAPIs) {
    for (inst_iterator i = inst_begin(FF), e = inst_end(FF); i != e; i++) {
      Instruction *I = &*i;
      if (auto *CI = dyn_cast<CallInst>(I)) {
        Function *F = CI->getCalledFunction();
        if (F && argContainMbuf(F)) {
          KA_LOGS(1, "adding " << F->getName() << " to LeakAPIs\n");
          addToFuncSet(F, tmpFuncSet);
        }
      }
    }
  }

  for (auto *FF : tmpFuncSet) {
    addToFuncSet(FF, Ctx->LeakAPIs);
  }

  for (auto *FF : Ctx->LeakAPIs) {
    KA_LOGS(0, "Function : " << FF->getName() << "\n");
  }
}

// determine leakable: track buffer and length argument in the leaking channel
// leakable if both arguments come from flexible structure's field
void LeakerAnalyzerPass::analyzeLeak(llvm::CallInst *callInst,
                                     std::string calleeName) {

  llvm::Function *F = callInst->getParent()->getParent();
  KA_LOGS(1, "\n<<<<<<<<< Analyzing calling to " + calleeName + "() in " +
                 F->getName().str() + "()\n");

  Value *len = nullptr;
  Value *buf = nullptr;
  ;

  if (calleeName == "put_user") {
    // FIXME, this is a macro
    // deal with this later if necessary

  } else if (calleeName == "copy_to_user") {
    if (callInst->getNumArgOperands() != 3) {
      KA_LOGS(1, "[-] Weird copy_to_user(): ");
      KA_LOGV(1, callInst);
      return;
    }

    len = callInst->getArgOperand(2);
    buf = callInst->getArgOperand(1);

  } else if (calleeName == "_copy_to_user") {
    if (callInst->getFunction()->getName() == "copy_to_user") {
      return;
    }
    if (callInst->getNumArgOperands() != 3) {
      KA_LOGS(1, "[-] Weird copy_to_user(): ");
      KA_LOGV(1, callInst);
      return;
    }

    len = callInst->getArgOperand(2);
    buf = callInst->getArgOperand(1);

  } else if (calleeName == "nla_put") {
    if (callInst->getNumArgOperands() != 4) {
      KA_LOGS(1, "[-] Weird nla_put(): ");
      KA_LOGV(1, callInst);
      return;
    }

    // Heuristic 2, duplicate with Heuristic 1 but save time and space
    if (F->getName().str() == "nla_put_string")
      return;

    len = callInst->getArgOperand(2);
    buf = callInst->getArgOperand(3);

  } else if (calleeName == "skb_put_data") {
    if (callInst->getNumArgOperands() != 3) {
      KA_LOGS(1, "[-] Weird skb_put_data(): ");
      KA_LOGV(1, callInst);
      return;
    }
    len = callInst->getArgOperand(2);
    buf = callInst->getArgOperand(1);
  } else if (calleeName == "nlmsg_data" || calleeName == "nla_data" ||
             calleeName == "skb_put") {

    // Heuristic 2, avoid duplication of leak site
    if (calleeName == "skb_put" && F->getName().str() == "skb_put_data")
      return;

    Value *V = callInst;
    // if return value is used as dst in memcpy
    checkChannelUsageinFunc(V, len, buf);
    for (Value::use_iterator ui = V->use_begin(), ue = V->use_end(); ui != ue;
         ui++) {
      if (auto *I = dyn_cast<Instruction>(ui->getUser())) {
        if (auto *callInst = dyn_cast<CallInst>(I)) {
          const Function *callee = callInst->getCalledFunction();
          if (callee == nullptr)
            continue;
          std::string calleeName = callee->getName().str();
          if (calleeName == "__memcpy" || calleeName == "memcpy" ||
              calleeName == "llvm.memcpy.p0i8.p0i8.i64") {
            len = callInst->getArgOperand(2);
            buf = callInst->getArgOperand(1);
            break;
          }
        }
      }
    }

    if (len == nullptr || buf == nullptr)
      return;

  }
#define XNU
#define FREEBSD
#ifdef XNU
  else if (calleeName == "copyout") {
    if (callInst->getNumArgOperands() != 3) {
      KA_LOGS(1, "[-] Weird copyout(): ");
      KA_LOGV(1, callInst);
      return;
    }

#ifdef FREEBSD
    // discard this copyout if it is called
    // by uiomove since we have marked uiomove
    // as a leaking channel
    Function *F = callInst->getFunction();
    if (F->getName() == "uiomove_faultflag") {
      return;
    }
#endif

    len = callInst->getArgOperand(2);
    buf = callInst->getArgOperand(0);
  } else if (Ctx->LeakAPIs.find(F) != Ctx->LeakAPIs.end()) {
    if (calleeName == "m_copyback") {
      buf = callInst->getArgOperand(3);
      len = callInst->getArgOperand(2);
    } else if (calleeName == "m_append") {
      buf = callInst->getArgOperand(2);
      len = callInst->getArgOperand(1);
    } else if (calleeName.find("memcpy") != std::string::npos) {
      Value *mbuf = callInst->getArgOperand(0);
      if (!isMbufData(mbuf))
        return;
      buf = callInst->getArgOperand(1);
      len = callInst->getArgOperand(2);
    }
  } else if (true) {
    return;
  }
#endif

#ifdef FREEBSD
  else if (calleeName == "uiomove") {
    buf = callInst->getArgOperand(0);
    len = callInst->getArgOperand(1);
  }
#endif
  else {
    RES_REPORT(calleeName << "\n");
    assert(false && "callee is not a leak channel");
  }

  assert(len != nullptr && buf != nullptr && "both len & buf are not nullptr");

  // KA_LOGS(1, "----- Tracing Buffer --------\n");

  // std::vector<Value *> srcBufSet;
  // std::set<Value *> trackedBufSet;
  // findSources(buf, srcBufSet, trackedBufSet);

  // check permission
  Function *body = callInst->getFunction();
  if (isPriviledged(body)) {
    outs() << body->getName() << " is priviledged function for leaking\n";
    return;
  }

  KA_LOGS(1, "----- Tracing Length --------\n");
  std::vector<Value *> srcLenSet;
  std::set<Value *> trackedLenSet;
  findSources(len, srcLenSet, trackedLenSet);

  Module *M = F->getParent();
  StructTypeSet &stSet = Ctx->moduleStructMap[M];

  KA_LOGS(1, "----- Setup SiteInfo Length -------\n");
  setupLeakInfo(srcLenSet, callInst, 0);
}

void LeakerAnalyzerPass::analyzeCopyIn(llvm::CallInst *callInst,
                                       std::string calleeName) {
  llvm::Function *F = callInst->getParent()->getParent();
  KA_LOGS(1, "\n<<<<<<<<< Analyzing calling to " + calleeName + "() in " +
                 F->getName().str() + "()\n");

  Value *len = nullptr;
  Value *buf = nullptr;
  ;

  /* the following is controllable obj */
  if (calleeName == "copy_from_user") {

    len = callInst->getArgOperand(2);
    buf = callInst->getArgOperand(0);

  } else if (calleeName == "_copy_from_user" ||
             calleeName == "strncpy_from_user") {
    /* make sure we are not in copy_from_user */
    // if (callInst->getFunction()->getName() != "copy_from_user") {
    //   return;
    // }
    if (callInst->getNumArgOperands() != 3) {
      KA_LOGS(1, "[-] Weird copy_from_user(): ");
      KA_LOGV(1, callInst);
      return;
    }

    len = callInst->getArgOperand(2);
    buf = callInst->getArgOperand(0);
  } else if (calleeName == "copyin") {
    KA_LOGS(0, "Found copyin\n");
    len = callInst->getArgOperand(2);
    buf = callInst->getArgOperand(0);
  } else {
    KA_LOGS(0, "Unknown callee " << calleeName << "\n");
    assert(false);
    return;
  }

  assert(len != nullptr && buf != nullptr && "both len & buf are not nullptr");

  KA_LOGS(1, "----- Tracing Buffer --------\n");

  std::vector<Value *> srcBufSet;
  std::set<Value *> trackedBufSet;
  findSources(buf, srcBufSet, trackedBufSet);

  KA_LOGS(1, "----- Setup SiteInfo Length -------\n");
  setupLeakInfo(srcBufSet, callInst, 1);
}

void LeakerAnalyzerPass::checkChannelUsageinFunc(Value *V, Value *&len,
                                                 Value *&buf) {

  for (Value::use_iterator ui = V->use_begin(), ue = V->use_end(); ui != ue;
       ui++) {
    if (auto *callInst = dyn_cast<CallInst>(ui->getUser())) {
      const Function *callee = callInst->getCalledFunction();
      if (callee == nullptr)
        continue;
      string calleeName = callee->getName().str();
      if (calleeName == "__memcpy" || calleeName == "memcpy" ||
          calleeName == "llvm.memcpy.p0i8.p0i8.i64") {
        len = callInst->getArgOperand(2);
        buf = callInst->getArgOperand(1);

        // make sure src != nla_data()
        if (buf == V) {
          buf = nullptr;
          len = nullptr;
        }
        return;
      }

    } else if (auto *BCI = dyn_cast<BitCastInst>(ui->getUser())) {
      checkChannelUsageinFunc(BCI, len, buf);
    } else if (auto *GEP = dyn_cast<GetElementPtrInst>(ui->getUser())) {
      checkChannelUsageinFunc(GEP, len, buf);
    }

    if (len != nullptr && buf != nullptr)
      return;
  }
}

SmallPtrSet<Value *, 16> LeakerAnalyzerPass::getAliasSet(Value *V,
                                                         Function *F) {

  SmallPtrSet<Value *, 16> null;
  null.clear();

  auto aliasMap = Ctx->FuncPAResults.find(F);
  if (aliasMap == Ctx->FuncPAResults.end())
    return null;

  auto alias = aliasMap->second.find(V);
  if (alias == aliasMap->second.end()) {
    return null;
  }

  return alias->second;
}

void LeakerAnalyzerPass::findSources(Value *V,
                                     std::vector<llvm::Value *> &srcSet,
                                     std::set<llvm::Value *> &trackedSet) {

  // Lewis: hard coded boundary to save time
  // and avoid stack overflow, I mean that "overflow", hahaha
  // TODO: solve alias in current function
  if (trackedSet.count(V) != 0 || trackedSet.size() >= 100)
    return;

  trackedSet.insert(V);
  KA_LOGS(2, "FindSource: Adding ");
  KA_LOGV(2, V);

  // FIXME: Not examining called function inside can introduce FP
  // Lewis: this guess hits, add one chicken leg tonight!
  if (CallInst *CI = dyn_cast<CallInst>(V)) {
    // Storing callInst helps to check from value type
    // srcSet.push_back(V);
    // // Heuristic 1: calling to strlen()/vmalloc() isn't what we want
    // const Function* callee = CI->getCalledFunction();
    // if (callee != nullptr) {
    //     std::string calleeName = callee->getName().str();
    //     if (calleeName == "strlen"||
    //         calleeName == "vmalloc")
    //         return;
    // }

    // if(!callee) return;
    // // interprocedural analysis
    // StringRef tmpName = callee->getName();
    // if(tmpName.lower().find("alloc") != string::npos
    //     || tmpName.lower().find("ALLOC") != string::npos
    //     || tmpName.lower().find("free") != string::npos
    //     || tmpName.lower().find("FREE") != string::npos
    // ){
    //     return;
    // }
    // KA_LOGS(1, "Starting interprocedural analysis for
    // "<<callee->getName().str()<<"\n"); for(const BasicBlock &BB : *callee){
    //     for(const Instruction &I : BB){
    //         if(const ReturnInst *RI = dyn_cast<ReturnInst>(&I)){
    //             if(Value *rValue = RI->getReturnValue()){
    //                 findSources(rValue, srcSet, trackedSet);
    //             }
    //         }
    //     }
    // }
    // comment this because interprocedural analysis will taint the interesting
    // arguments for (auto AI = CI->arg_begin(), E = CI->arg_end(); AI != E;
    // AI++) {
    //     Value* Param = dyn_cast<Value>(&*AI);
    //     findSources(Param, srcSet, trackedSet);
    // }
    return;
  }

  if (BitCastInst *BCI = dyn_cast<BitCastInst>(V)) {
    srcSet.push_back(V);
    findSources(BCI->getOperand(0), srcSet, trackedSet);
    return;
  }

  if (dyn_cast<AllocaInst>(V)) {
    srcSet.push_back(V);
    return;
  }

  if (dyn_cast<ConstantPointerNull>(V)) {
    srcSet.push_back(V);
    return;
  }

  if (dyn_cast<Constant>(V)) {
    srcSet.push_back(V);
    return;
  }

  // Lewis: it is impossible but leave this in case
  // zipline: we need to handle this
  if (dyn_cast<GlobalVariable>(V)) {
    Constant *Ct = dyn_cast<Constant>(V);
    if (!Ct)
      return;
    srcSet.push_back(V);
    return;
  }

  // Lewis: it is impossible but leave this in case
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(V)) {
    findSources(CE->getOperand(0), srcSet, trackedSet);
    return;
  }

  if (Argument *A = dyn_cast<Argument>(V)) {
    // srcSet.push_back(V);
    // // return; // intra-procedural

    // // inter-procedural analysis begins following
    // Function *callee = A->getParent();
    // if (callee == nullptr)
    //   return;

    // for (CallInst *caller : Ctx->Callers[callee]) {
    //   if (caller) {
    //     // Lewis: this should never happen
    //     if (A->getArgNo() >= caller->getNumArgOperands())
    //       continue;
    //     Value *arg = caller->getArgOperand(A->getArgNo());
    //     if (arg == nullptr)
    //       continue;

    //     Function *F = caller->getParent()->getParent();
    //     KA_LOGS(1,
    //             "<<<<<<<<< Cross Analyzing " << F->getName().str() <<
    //             "()\n");
    //     KA_LOGV(1, caller);
    //     findSources(arg, srcSet, trackedSet);
    //   }
    // }
    return;
  }

  if (LoadInst *LI = dyn_cast<LoadInst>(V)) {

    // srcSet.push_back(V);

    // // alias handling
    // Function *F = LI->getFunction();

    // if (!F)
    //   return;

    // SmallPtrSet<Value *, 16> aliasSet;
    // bool foundStore = false;

    // aliasSet = getAliasSet(LI->getPointerOperand(), F);

    // // add Load's pointer operand to the set
    // // it may have a store successor
    // aliasSet.insert(LI->getPointerOperand());

    // for (auto *alias : aliasSet) {
    //   for (auto *aliasUser : alias->users()) {
    //     if (auto *SI = dyn_cast<StoreInst>(aliasUser)) {
    //       foundStore |= true;
    //       KA_LOGS(1, "FindSource: resolved an alias : " << *LI << " == " <<
    //       *SI
    //                                                     << "\n");
    //       findSources(SI->getValueOperand(), srcSet, trackedSet);
    //     }
    //   }
    // }

    // // return because it maybe loading from a stack value
    // // since we can found a corresponding store
    // if (foundStore)
    //   return;

    // findSources(LI->getPointerOperand(), srcSet, trackedSet);
    return;
  }

  if (StoreInst *SI = dyn_cast<StoreInst>(V)) {
    // findSources(SI->getValueOperand(), srcSet, trackedSet);
  }

  if (SelectInst *SI = dyn_cast<SelectInst>(V)) {
    findSources(SI->getTrueValue(), srcSet, trackedSet);
    findSources(SI->getFalseValue(), srcSet, trackedSet);
    return;
  }

  if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {
    // TODO f**k aliases
    KA_LOGS(1, "Here may contain an alias, please check this\n");
    DEBUG_Inst(2, GEP);
    srcSet.push_back(V);
    // Heuristic 2: first GEP is enough?
    // Lewis: Wrong
    findSources(GEP->getPointerOperand(), srcSet, trackedSet);
    return;
  }

  if (PHINode *PN = dyn_cast<PHINode>(V)) {
    for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; i++) {
      Value *IV = PN->getIncomingValue(i);
      findSources(IV, srcSet, trackedSet);
    }
    return;
  }

  if (ICmpInst *ICmp = dyn_cast<ICmpInst>(V)) {
    for (unsigned i = 0, e = ICmp->getNumOperands(); i != e; i++) {
      Value *Opd = ICmp->getOperand(i);
      findSources(Opd, srcSet, trackedSet);
    }
    return;
  }

  if (BinaryOperator *BO = dyn_cast<BinaryOperator>(V)) {
    for (unsigned i = 0, e = BO->getNumOperands(); i != e; i++) {
      Value *Opd = BO->getOperand(i);
      if (dyn_cast<Constant>(Opd))
        continue;
      findSources(Opd, srcSet, trackedSet);
    }
    return;
  }

  if (UnaryInstruction *UI = dyn_cast<UnaryInstruction>(V)) {
    findSources(UI->getOperand(0), srcSet, trackedSet);
    return;
  }

  return;
}

void LeakerAnalyzerPass::addLeakInst(StructInfo *stInfo,
                                     llvm::CallInst *callInst, unsigned offset,
                                     llvm::Instruction *I,
                                     llvm::StructType *st) {

  if (!stInfo)
    return;

  if (stInfo->leakInst.find(callInst) != stInfo->leakInst.end())
    return;

  stInfo->leakInst.insert(callInst);

  LeakStructMap::iterator it = Ctx->leakStructMap.find(stInfo->name);
  if (it == Ctx->leakStructMap.end()) {
    Ctx->leakStructMap.insert(std::make_pair(stInfo->name, stInfo));
  }

  KA_LOGS(1, "Add " << stInfo->name << " successful\n");

  if (offset == -1)
    return;

  // add other SiteInfo in the future
  StructInfo::SiteInfo sInfo;
  sInfo.lenValue = I;
  sInfo.lenSt = st;
  stInfo->addLeakSourceInfo(offset, dyn_cast<Value>(callInst), sInfo);
}

void LeakerAnalyzerPass::setupLeakInfo(std::vector<Value *> &srcSet,
                                       CallInst *callInst, bool copyin) {
  for (std::vector<llvm::Value *>::iterator i = srcSet.begin(),
                                            e = srcSet.end();
       i != e; i++) {

    Value *V = *i;

    if (auto *AI = dyn_cast<AllocaInst>(V)) {
      Ctx->DataOnStackCalls.insert(callInst);
    }
    continue;

    if (auto *LI = dyn_cast<LoadInst>(V)) {

      KA_LOGS(1, "[Load] ");
      KA_LOGV(1, LI);

      // check if it's loading a pointer
      // Type *type = LI->getPointerOperandType();
      // if(type->getPointerElementType()->isPointerTy()){
      //     continue;
      // }

      Value *lValue = LI->getPointerOperand();
      while (auto *GEP = dyn_cast<GetElementPtrInst>(lValue)) {
        KA_LOGS(1, "[GEP] ");
        KA_LOGV(1, GEP);

        // only pointer value
        if (GEP->getNumIndices() == 1)
          break;

        PointerType *ptrType =
            dyn_cast<PointerType>(GEP->getPointerOperandType());
        assert(ptrType != nullptr);
        Type *baseType = ptrType->getElementType();
        StructType *stType = dyn_cast<StructType>(baseType);
        if (stType == nullptr)
          break;

        ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
        assert(CI != nullptr && "GEP's index is not constant");
        uint64_t offset = CI->getZExtValue();

        Module *M = GEP->getModule();
        StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

        if (!stInfo)
          break;

        // // we found length info
        // addLeakInst(stInfo, callInst, offset, GEP, stType);
        // // let's find source info
        // std::vector<Value *> srcFromSet;
        // std::set<Value *> trackedFromSet;
        // findSources(from, srcFromSet, trackedFromSet);
        // setupFromInfo(srcFromSet, stInfo, callInst, offset);

        KA_LOGS(2, "we found leakable / controllable obj " << stInfo->name
                                                           << copyin << "\n");

        if (copyin) {
          stInfo->controllable = true;
          stInfo->controllableOffset = offset;
          stInfo->copyinInst.insert(callInst);
        } else {
          stInfo->leakable = true;
          stInfo->leakableOffset = offset;
          stInfo->copyoutInst.insert(callInst);
        }

        // next loop
        // lValue = dyn_cast<Value>(GEP->getPointerOperand());
        break;
      }
    }
  }
}

void LeakerAnalyzerPass::setupFromInfo(std::vector<llvm::Value *> &srcSet,
                                       StructInfo *stInfo, CallInst *callInst,
                                       unsigned offset) {
  // FIXME: plz keep tracking whether the value is from stack or heap
  // after finding its type.
  StructInfo::SiteInfo *siteInfo =
      stInfo->getSiteInfo(offset, dyn_cast<Value>(callInst));

  if (siteInfo == nullptr)
    return;

  for (std::vector<llvm::Value *>::iterator i = srcSet.begin(),
                                            e = srcSet.end();
       i != e; i++) {

    Value *V = *i;

    KA_LOGS(2, "setupFromInfo : " << *V << "\n");

    if (auto *CPointerNull = dyn_cast<ConstantPointerNull>(V)) {

      siteInfo->fromValue = V;

      PointerType *ptrType = CPointerNull->getType();
      Type *baseType = ptrType->getElementType();
      StructType *stType = dyn_cast<StructType>(baseType);

      if (!stType) {
        return;
      }
      if (stType->getName().find("union.anon") != string::npos ||
          stType->getName().find("struct.anon") != string::npos) {
        return;
      }

      if (stType->getName() == stInfo->name) {
        siteInfo->TYPE = HEAP_SAME_OBJ;
      } else {
        siteInfo->TYPE = HEAP_DIFF_OBJ;
      }
      siteInfo->fromSt = stType;
      return;
    } else if (auto *allocInst = dyn_cast<AllocaInst>(V)) {

      Type *type = allocInst->getAllocatedType();

      if (!type->isPointerTy()) {
        siteInfo->TYPE = STACK;
        siteInfo->fromValue = V;
      } else {
        siteInfo->TYPE = HEAP_DIFF_OBJ;
        siteInfo->fromValue = V;
      }
      StructType *stType = dyn_cast<StructType>(type);
      if (stType) {
        siteInfo->fromSt = stType;
      }
      return;

    } else if (dyn_cast<LoadInst>(V) || dyn_cast<GetElementPtrInst>(V)) {

      auto *LI = dyn_cast<LoadInst>(V);
      Value *lValue = V;
      GetElementPtrInst *GEP = nullptr;
      Instruction *I = nullptr;

      if (LI) {
        // return on load anyway.
        lValue = LI->getPointerOperand();
        PointerType *ptrType =
            dyn_cast<PointerType>(LI->getPointerOperandType());
        Type *baseType = ptrType->getElementType();
        StructType *stType = dyn_cast<StructType>(baseType);
        if (stType == nullptr)
          continue;

        Module *M = LI->getModule();
        StructInfo *stInfoFrom = Ctx->structAnalyzer.getStructInfo(stType, M);

        if (!stInfoFrom || stType->getName().find("union.anon") == 0 ||
            stType->getName().find("struct.anon") == 0)
          continue;

        if (stInfo->name == stInfoFrom->name) {
          // we found it
          siteInfo->TYPE = HEAP_SAME_OBJ;
        } else {
          siteInfo->TYPE = HEAP_DIFF_OBJ;
        }

        siteInfo->fromSt = stType;
        siteInfo->fromValue = LI;
        return;
      }

      for (GEP = dyn_cast<GetElementPtrInst>(lValue); GEP;
           GEP = dyn_cast<GetElementPtrInst>(I->getOperand(0))) {

        KA_LOGS(2, "[GEP] in setupFromInfo " << *GEP << "\n");

        if (!GEP->getPointerOperand())
          break;

        I = GEP;

        if (auto *BCI = dyn_cast<BitCastInst>(GEP->getPointerOperand())) {
          I = BCI;
        }

        // only pointer value
        if (GEP->getNumIndices() == 1)
          continue;

        PointerType *ptrType =
            dyn_cast<PointerType>(GEP->getPointerOperandType());
        assert(ptrType != nullptr);
        Type *baseType = ptrType->getElementType();
        StructType *stType = dyn_cast<StructType>(baseType);
        if (stType == nullptr)
          continue;

        Module *M = GEP->getModule();
        StructInfo *stInfoFrom = Ctx->structAnalyzer.getStructInfo(stType, M);

        if (!stInfoFrom || stType->getName().find("union.anon") == 0 ||
            stType->getName().find("struct.anon") == 0)
          continue;

        if (stInfo->name == stInfoFrom->name) {
          // we found it
          siteInfo->TYPE = HEAP_SAME_OBJ;
        }

        siteInfo->fromSt = stType;
        siteInfo->fromValue = GEP;
        // return;
      }
    } else if (auto *BCI = dyn_cast<BitCastInst>(V)) {
      KA_LOGS(1, "[BitCast] in setupFromInfo");
      KA_LOGV(1, V);

      PointerType *ptrType = dyn_cast<PointerType>(BCI->getSrcTy());
      assert(ptrType != nullptr);
      Type *baseType = ptrType->getElementType();

      StructType *stType = dyn_cast<StructType>(baseType);
      if (stType == nullptr)
        continue;

      Module *M = BCI->getParent()->getParent()->getParent();
      StructInfo *stInfoFrom = Ctx->structAnalyzer.getStructInfo(stType, M);

      if (!stInfoFrom || stType->getName().find("union.anon") == 0 ||
          stType->getName().find("struct.anon") == 0)
        continue;

      // FIXME: what if siteInfo has already been set?

      if (stInfoFrom->name == stInfo->name) {
        siteInfo->TYPE = HEAP_SAME_OBJ;
      }

      siteInfo->fromSt = stType;
      siteInfo->fromValue = BCI;
      // return;
    } else if (auto *callInst = dyn_cast<CallInst>(V)) {
      KA_LOGS(1, "[CallInst] in setupFromInfo " << *callInst << "\n");
      Function *callee = callInst->getCalledFunction();
      if (!callee)
        callee =
            dyn_cast<Function>(callInst->getCalledValue()->stripPointerCasts());
      if (callee) {

        // we assume all functions return memory coming from heap
        std::string calleeName = callee->getName().str();
        siteInfo->fromValue = callInst;
        siteInfo->TYPE = HEAP_DIFF_OBJ;

        if (calleeName == "m_mtod") {
          if (stInfo->name == "mbuf")
            siteInfo->TYPE = HEAP_SAME_OBJ;

          // find mbuf
          // use this for compatibility issue
          // Value *arg = callee->getArg(0);
          Value *arg = callee->arg_begin();
          Type *t = arg->getType()->getPointerElementType();
          if (auto *st = dyn_cast<StructType>(t)) {
            siteInfo->fromSt = st;
          }
          return;
        } else {
          if (siteInfo->fromSt) {
            if (siteInfo->fromSt->getName() == stInfo->name) {
              siteInfo->TYPE = HEAP_SAME_OBJ;
            }
            return;
          }
          // get return type if no bitcast after calling a function
          Type *type = callee->getReturnType();
          if (auto *st = dyn_cast<StructType>(type)) {
            if (st->getName() == stInfo->name) {
              siteInfo->TYPE = HEAP_SAME_OBJ;
            }
            siteInfo->fromSt = st;
          }
          return;
        }
      }

    } else if (dyn_cast<Argument>(V)) {
      return;
    }
  }
}

llvm::StructType *
LeakerAnalyzerPass::checkSource(std::vector<llvm::Value *> &srcSet,
                                StructTypeSet &stSet, CallInst *callInst,
                                bool isLen) {

  // Heuristic 2, check source from close to remote
  for (std::vector<llvm::Value *>::iterator i = srcSet.begin(),
                                            e = srcSet.end();
       i != e; i++) {

    llvm::Value *V = *i;

    if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {

      KA_LOGS(1, "[GEP] ");
      KA_LOGV(1, V);

      // only pointer value
      if (GEP->getNumIndices() == 1)
        continue;

      PointerType *ptrType =
          dyn_cast<PointerType>(GEP->getPointerOperandType());
      assert(ptrType != nullptr);
      Type *baseType = ptrType->getElementType();
      StructType *stType = dyn_cast<StructType>(baseType);
      if (stType == nullptr)
        continue;

      ConstantInt *CI = dyn_cast<ConstantInt>(GEP->getOperand(2));
      assert(CI != nullptr && "GEP's index is not constant");
      uint64_t idx = CI->getZExtValue();

      Module *M = GEP->getParent()->getParent()->getParent();
      StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

      if (!stInfo)
        continue;

      addLeakInst(stInfo, callInst, idx, GEP, stType);

      // situation 1: return value refers to buffer in the flexible structure
      // if (stSet.find(stType) != stSet.end()) {
      // if (stInfo->flexibleStructFlag) {
      //     if (isLen) {
      //         stInfo->lenOffsetByLeakable.push_back(idx);
      //         KA_LOGS(1, "[+] update length field offset: " << idx << "\n");
      //         return stType;
      //     } else if (idx == (stType->element_end() - stType->element_begin()
      //     - 1)) {
      //         return stType;
      //     }
      // } else {
      //     // situation 2: return value refers to flexible structure
      //     Type* idxType = stType->getElementType(idx);
      //     PointerType* ptrType = dyn_cast<PointerType>(idxType);
      //     if (ptrType == nullptr)
      //         continue;
      //     Type* subType = ptrType->getElementType();
      //     StructType* subSTType = dyn_cast<StructType>(subType);
      //     if (subSTType == nullptr)
      //         continue;

      //     stInfo = Ctx->structAnalyzer.getStructInfo(subSTType, M);

      //     if(!stInfo) continue;

      //     // if (stSet.find(subSTType) != stSet.end()) {
      //     if (stInfo->flexibleStructFlag) {
      //         if (isLen)
      //             KA_LOGS(1, "[-] no length field update, FIXME 1\n");
      //         return subSTType;
      //     }
      // }

    } else if (LoadInst *LI = dyn_cast<LoadInst>(V)) {

      KA_LOGS(1, "[Load] ");
      KA_LOGV(1, V);

      PointerType *ptrType = dyn_cast<PointerType>(LI->getPointerOperandType());
      assert(ptrType != nullptr);
      Type *baseType = ptrType->getElementType();

      // situation 1: pointer itself refers flexible structure
      if (StructType *stType = dyn_cast<StructType>(baseType)) {

        Module *M = LI->getParent()->getParent()->getParent();
        StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

        if (!stInfo)
          continue;

        // if (stSet.find(stType) != stSet.end()) {
        if (stInfo->flexibleStructFlag) {
          if (isLen)
            KA_LOGS(1, "[-] no length field update, FIXME 2\n");
          return stType;
        }
      } else if (PointerType *ptrType = dyn_cast<PointerType>(baseType)) {
        KA_LOGS(1, "[-] load from a pointer\n");
      }

    } else if (BitCastInst *BCI = dyn_cast<BitCastInst>(V)) {

      KA_LOGS(1, "[BitCast] ");
      KA_LOGV(1, V);

      PointerType *ptrType = dyn_cast<PointerType>(BCI->getSrcTy());
      assert(ptrType != nullptr);
      Type *baseType = ptrType->getElementType();

      StructType *stType = dyn_cast<StructType>(baseType);
      if (stType == nullptr)
        continue;

      Module *M = BCI->getParent()->getParent()->getParent();
      StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

      if (!stInfo)
        continue;

      // if (stSet.find(stType) != stSet.end()) {
      if (stInfo->flexibleStructFlag) {
        if (isLen)
          KA_LOGS(1, "[-] no length field update, FIXME 3\n");
        return stType;
      }

    } else if (Argument *A = dyn_cast<Argument>(V)) {

      KA_LOGS(1, "[Arg] ");
      KA_LOGV(1, V);

      PointerType *ptrType = dyn_cast<PointerType>(A->getType());
      if (ptrType == nullptr)
        continue;

      Type *baseType = ptrType->getElementType();
      StructType *stType = dyn_cast<StructType>(baseType);
      if (stType == nullptr)
        continue;

      Module *M = A->getParent()->getParent();
      StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);

      if (!stInfo)
        continue;

      // if (stSet.find(stType) != stSet.end()) {
      if (stInfo->flexibleStructFlag) {
        if (isLen)
          KA_LOGS(1, "[-] no length field update, FIXME 4\n");
        return stType;
      }

    } else {
      KA_LOGS(1, "[-] add support for: ");
      KA_LOGV(1, V);
    }
  }
  return nullptr;
}

// join allocInstMap and leakInstMap to compute moduleStructMap
// reverse moduleStructMap to obtain structModuleMap
// reachable analysis to compute allocSyscallMap and leakSyscallMap
// join allocSyscallMap and leakSyscallMap to compute leakerList
bool LeakerAnalyzerPass::doFinalization(Module *M) {

  KA_LOGS(1, "[Finalize] " << M->getModuleIdentifier() << "\n");
  ModuleStructMap::iterator it = Ctx->moduleStructMap.find(M);
  assert(it != Ctx->moduleStructMap.end() &&
         "M is not analyzed in doInitialization");

  if (it->second.size() == 0) {
    KA_LOGS(1, "No flexible structure in this module\n");
    return false;
  }

  KA_LOGS(1, "Building moduleStructMap ...\n");
  // moduleStructMap: map module to flexible struct "st"
  StructTypeSet tmpStructTypeSet = Ctx->moduleStructMap[M];
  for (StructTypeSet::iterator itr = tmpStructTypeSet.begin(),
                               ite = tmpStructTypeSet.end();
       itr != ite; itr++) {

    StructType *st = *itr;
    std::string structName = getScopeName(st, M);

    LeakInstMap::iterator liit = Ctx->leakInstMap.find(structName);
    // XXX
    // AllocInstMap::iterator aiit = Ctx->allocInstMap.find(structName);

    // either leak or alloc or both
    if (liit == Ctx->leakInstMap.end())
      // XXX
      //  || aiit == Ctx->allocInstMap.end() )
      Ctx->moduleStructMap[M].erase(st);
  }

  if (Ctx->moduleStructMap[M].size() == 0) {
    KA_LOGS(1, "Actually no flexible structure in this module\n");
    return false;
  }

  KA_LOGS(1, "Building structModuleMap ...\n");
  // structModuleMap: map flexible struct "st" to module
  for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(),
                               ite = Ctx->moduleStructMap[M].end();
       itr != ite; itr++) {

    StructType *st = *itr;
    std::string structName = getScopeName(st, M);

    StructModuleMap::iterator sit = Ctx->structModuleMap.find(structName);
    if (sit == Ctx->structModuleMap.end()) {
      ModuleSet moduleSet;
      moduleSet.insert(M);
      Ctx->structModuleMap.insert(std::make_pair(structName, moduleSet));
    } else {
      sit->second.insert(M);
    }
  }

  KA_LOGS(1, "Building leakSyscallMap & allocSyscallMap ...\n");
  // leakSyscallMap: map structName to syscall reaching leak sites
  // allocSyscallMap: map structName to syscall reaching allocation sites
  for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(),
                               ite = Ctx->moduleStructMap[M].end();
       itr != ite; itr++) {

    StructType *st = *itr;
    std::string structName = getScopeName(st, M);

    // leakSyscallMap
    // XXX
    KA_LOGS(1, "Dealing with leaking: " << structName << "\n");
    LeakInstMap::iterator liit = Ctx->leakInstMap.find(structName);
    LeakSyscallMap::iterator lsit = Ctx->leakSyscallMap.find(structName);
    if (liit != Ctx->leakInstMap.end() &&
        lsit == Ctx->leakSyscallMap.end() // to avoid redundant computation
    ) {
      for (auto I : liit->second) {

        Function *F = I->getParent()->getParent();
        FuncSet syscallSet = reachableSyscall(F);
        if (syscallSet.size() == 0)
          continue;

        LeakSyscallMap::iterator lsit = Ctx->leakSyscallMap.find(structName);
        if (lsit == Ctx->leakSyscallMap.end())
          Ctx->leakSyscallMap.insert(std::make_pair(structName, syscallSet));
        else
          for (auto F : syscallSet)
            lsit->second.insert(F);
      }
    }

    // allocSyscallMap
    // XXX
    /*
    KA_LOGS(1, "Dealing with allocating: " << structName << "\n");
    AllocInstMap::iterator aiit = Ctx->allocInstMap.find(structName);
    AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
    if (aiit != Ctx->allocInstMap.end() &&
        asit == Ctx->allocSyscallMap.end()
        ) {
        for (auto I : aiit->second) {

            Function* F = I->getParent()->getParent();
            FuncSet syscallSet = reachableSyscall(F);
            if (syscallSet.size() == 0)
                continue;

            AllocSyscallMap::iterator asit =
    Ctx->allocSyscallMap.find(structName); if (asit ==
    Ctx->allocSyscallMap.end())
                Ctx->allocSyscallMap.insert(std::make_pair(structName,
    syscallSet)); else for (auto F : syscallSet) asit->second.insert(F);
        }
    }
    */
  }

  KA_LOGS(1, "Building leakerList ...\n");
  for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(),
                               ite = Ctx->moduleStructMap[M].end();
       itr != ite; itr++) {

    StructType *st = *itr;
    std::string structName = getScopeName(st, M);

    LeakSyscallMap::iterator lsit = Ctx->leakSyscallMap.find(structName);
    // XXX
    // AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);

    if (lsit == Ctx->leakSyscallMap.end())
      // XXX
      // || asit == Ctx->allocSyscallMap.end())
      continue;

    LeakerList::iterator tit = Ctx->leakerList.find(structName);
    if (tit == Ctx->leakerList.end()) {
      InstSet instSet;
      for (auto I : Ctx->leakInstMap[structName])
        instSet.insert(I);
      Ctx->leakerList.insert(std::make_pair(structName, instSet));

    } else {
      for (auto I : Ctx->leakInstMap[structName])
        tit->second.insert(I);
    }
  }
  return false;
}

FuncSet LeakerAnalyzerPass::getSyscalls(Function *F) {
  ReachableSyscallCache::iterator it = reachableSyscallCache.find(F);
  if (it != reachableSyscallCache.end())
    return it->second;
  FuncSet null;
  return null;
}

FuncSet LeakerAnalyzerPass::reachableSyscall(llvm::Function *F) {

  ReachableSyscallCache::iterator it = reachableSyscallCache.find(F);
  if (it != reachableSyscallCache.end())
    return it->second;

  FuncSet reachableFuncs;
  reachableFuncs.clear();

  FuncSet reachableSyscalls;
  reachableSyscalls.clear();

  SmallVector<Function *, 4> workList;
  workList.clear();
  workList.push_back(F);

  while (!workList.empty()) {
    Function *F = workList.pop_back_val();
    if (!reachableFuncs.insert(F).second)
      continue;

    if (reachableSyscallCache.find(F) != reachableSyscallCache.end()) {
      FuncSet RS = getSyscalls(F);
      for (auto *RF : RS) {
        reachableFuncs.insert(RF);
      }
      continue;
    }

    CallerMap::iterator it = Ctx->Callers.find(F);
    if (it != Ctx->Callers.end()) {
      for (auto calleeInst : it->second) {
        Function *F = calleeInst->getParent()->getParent();
        workList.push_back(F);
      }
    }
  }

  for (auto F : reachableFuncs) {
    StringRef funcNameRef = F->getName();
    std::string funcName = "";
    if (funcNameRef.startswith("__sys_")) {
      funcName = "sys_" + funcNameRef.str().substr(6);
    } else if (funcNameRef.startswith("__x64_sys_")) {
      funcName = "sys_" + funcNameRef.str().substr(9);
    } else if (funcNameRef.startswith("__ia32_sys")) {
      funcName = "sys_" + funcNameRef.str().substr(10);
    } else if (funcNameRef.startswith("__se_sys")) {
      funcName = "sys_" + funcNameRef.str().substr(8);
    }

    if (funcName != "") {
      if (std::find(rootSyscall.begin(), rootSyscall.end(), funcName) ==
          rootSyscall.end()) {
        reachableSyscalls.insert(F);
      }
    }
  }

  reachableSyscallCache.insert(std::make_pair(F, reachableSyscalls));
  return reachableSyscalls;
}

void LeakerAnalyzerPass::dumpSimplifiedLeakers() {
  for (LeakStructMap::iterator it = Ctx->leakStructMap.begin(),
                               e = Ctx->leakStructMap.end();
       it != e; it++) {

    StructInfo *st = it->second;
    if (st->leakInfo.size() == 0)
      continue;
    st->dumpSimplified();
  }
  return;
}

bool LeakerAnalyzerPass::containIndirectCall(Function *F) {
  if (F->hasSection() && F->getSection().str() == ".init.text")
    return false;
  // auto CISet = Ctx->IndirectCallMaps.find(F);
  // if (CISet.size() > 0)
  //   return true;

  if (Ctx->IndirectCallFuncs.find(F) != Ctx->IndirectCallFuncs.end()) {
    return true;
  }
  return false;
}

void LeakerAnalyzerPass::dumpDataOnStackFunc() {
  KA_LOGS(0, "Data on Stack Funcs:\n");
  for (auto CI : Ctx->DataOnStackCalls) {
    unsigned int size = 0;
    Function *F = CI->getFunction();
    if (isa<ConstantInt>(CI->getOperand(2))) {
      size = cast<ConstantInt>(CI->getOperand(2))->getZExtValue();
    }
    string loc = "(NO DEBUG INFO)";
    DILocation *DbgLoc = CI->getDebugLoc();
    if (DbgLoc) {
      loc = DbgLoc->getScope()->getFilename().str() + ":";
      loc += std::to_string(DbgLoc->getLine());
    }

    Function *getCalled = CI->getCalledFunction();
    if (size != 0)
      KA_LOGS(0, F->getName()
                     << "\tat " << loc << ", Function " << getCalled->getName()
                     << ", copy size " << size << ";");
    else
      KA_LOGS(0, F->getName()
                     << "\tat " << loc << ", Function " << getCalled->getName()
                     << ", copy size determined at runtime;");

    // check if it contains a indirect call in callees
    FuncSet visited;
    visited.clear();
    SmallVector<Function *, 4> workList;
    workList.clear();
    workList.push_back(CI->getFunction());
    bool containIndirect = false;
    while (!workList.empty()) {
      Function *cur = workList.pop_back_val();
      // KA_LOGS(0, "analyzing function " << cur->getName() << "\n");
      if (containIndirectCall(cur)) {
        containIndirect = true;
        break;
      }

      if (!visited.insert(cur).second) {
        continue;
      }

      for (inst_iterator i = inst_begin(cur), e = inst_end(cur); i != e; ++i) {
        Instruction *I = &*i;
        if (CallInst *CC = dyn_cast<CallInst>(I)) {
          Function *next = CC->getCalledFunction();
          if (!next)
            continue;
          workList.push_back(next);
        }
      }
    }

    if (containIndirect) {
      for (auto FF : visited) {
        Ctx->IndirectCallFuncs.insert(FF);
      }
      KA_LOGS(0, "\t\t This Function contains indirect calls\n");
    } else
      KA_LOGS(0, "\t\t This Function does not contain indirect calls\n");
  }
  return;
}

// dump final moduleStructMap and structModuleMap for debugging
void LeakerAnalyzerPass::dumpLeakers() {

  RES_REPORT("\n=========  printing LeakStructMap ==========\n");

  for (LeakStructMap::iterator it = Ctx->leakStructMap.begin(),
                               e = Ctx->leakStructMap.end();
       it != e; it++) {

    // RES_REPORT("[+] " << it->first << "\n");

    StructInfo *st = it->second;

    if (st->leakInfo.size() == 0)
      continue;

    if (VerboseLevel > 0) {
      st->dumpLeakInfo(false);
    } else {
      st->dumpLeakInfo(true);
      // skip print syscall map if no allocaInst or no leakInst
      if (!st->allocaInst.size() || !st->leakInst.size())
        continue;
    }

    // dump syscall info

    FuncSet SYSs;
    SYSs.clear();

    RES_REPORT("[+] syscalls:\n");
    for (auto *I : st->allocaInst) {
      Function *F = I->getFunction();
      if (!F)
        continue;
      FuncSet syscalls = getSyscalls(F);
      for (auto *SF : syscalls) {
        SYSs.insert(SF);
      }
    }
    for (auto *I : st->leakInst) {
      Function *F = I->getFunction();
      if (!F)
        continue;
      FuncSet syscalls = getSyscalls(F);
      for (auto *SF : syscalls) {
        SYSs.insert(SF);
      }
    }
    for (auto *SF : SYSs) {
      RES_REPORT(SF->getName() << "\n");
    }
    RES_REPORT("\n");
  }

  RES_REPORT("======= end printting LeakStructMap =========\n");

  if (VerboseLevel >= 3) {
    // dump alias
    for (auto const &alias : Ctx->FuncPAResults) {
      KA_LOGS(2, "Function: " << getScopeName(alias.first) << "\n");
      for (auto const &aliasMap : alias.second) {
        KA_LOGS(2,
                "Start dumping alias of Pointer : " << *aliasMap.first << "\n");
        for (auto *pointer : aliasMap.second) {
          KA_LOGS(2, *pointer << "\n");
        }
        KA_LOGS(2, "End dumping\n");
      }
      KA_LOGS(2, "\nEnding Function\n\n");
    }
  }

  unsigned cnt = 0;
  RES_REPORT("\n=========  printing moduleStructMap ==========\n");
  for (ModuleStructMap::iterator i = Ctx->moduleStructMap.begin(),
                                 e = Ctx->moduleStructMap.end();
       i != e; i++) {

    Module *M = i->first;
    StructTypeSet &stSet = i->second;

    RES_REPORT("[+] " << M->getModuleIdentifier() << "\n");

    for (StructType *st : stSet) {
      RES_REPORT(getScopeName(st, M) << "\n");
      const StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(st, M);
      RES_REPORT("Offset by Flexible: ");
      for (auto offset : stInfo->lenOffsetByFlexible)
        RES_REPORT(offset << ", ");
      RES_REPORT("\n");

      RES_REPORT("Offset by Leakable: ");
      for (auto offset : stInfo->lenOffsetByLeakable)
        RES_REPORT(offset << ", ");
      RES_REPORT("\n");
    }
  }
  RES_REPORT("======= end printting moduleStructMap =========\n");

  RES_REPORT("\n=========  printing structModuleMap ==========\n");
  cnt = 0;
  for (StructModuleMap::iterator i = Ctx->structModuleMap.begin(),
                                 e = Ctx->structModuleMap.end();
       i != e; i++, cnt++) {

    std::string structName = i->first;
    ModuleSet &moduleSet = i->second;

    RES_REPORT("[" << cnt << "] " << structName << "\n");
    for (Module *M : moduleSet)
      RES_REPORT("-- " << M->getModuleIdentifier() << "\n");
  }
  RES_REPORT("====== end printing structModuleMap ==========\n");

  RES_REPORT("\n=========  printing leakInstMap ==========\n");
  cnt = 0;
  for (AllocInstMap::iterator i = Ctx->leakInstMap.begin(),
                              e = Ctx->leakInstMap.end();
       i != e; i++, cnt++) {

    std::string structName = i->first;
    InstSet &instSet = i->second;

    RES_REPORT("[" << cnt << "] " << structName << "\n");

    for (Instruction *I : instSet) {
      Function *F = I->getParent()->getParent();

      RES_REPORT("-- " << F->getName().str() << "(), "
                       << F->getParent()->getModuleIdentifier() << "\n");
      RES_REPORT("   ");
      I->print(errs());
      RES_REPORT("\n");
    }
  }
  RES_REPORT("====== end printing leakInstMap ==========\n");

  RES_REPORT("\n=========  printing allocInstMap ==========\n");
  cnt = 0;
  for (AllocInstMap::iterator i = Ctx->allocInstMap.begin(),
                              e = Ctx->allocInstMap.end();
       i != e; i++, cnt++) {

    std::string structName = i->first;
    InstSet &instSet = i->second;

    RES_REPORT("[" << cnt << "] " << structName << "\n");

    for (Instruction *I : instSet) {
      Function *F = I->getParent()->getParent();

      RES_REPORT("-- " << F->getName().str() << "(), "
                       << F->getParent()->getModuleIdentifier() << "\n");
      RES_REPORT("   ");
      I->print(errs());
      RES_REPORT("\n");
    }
  }
  RES_REPORT("====== end printing allocInstMap ==========\n");

  RES_REPORT("\n=========  printing leakerList ==========\n");
  cnt = 0;
  for (LeakerList::iterator i = Ctx->leakerList.begin(),
                            e = Ctx->leakerList.end();
       i != e; i++, cnt++) {

    std::string structName = i->first;
    InstSet &instSet = i->second;

    RES_REPORT("[" << cnt << "] " << structName << "\n");

    for (Instruction *I : instSet) {
      Function *F = I->getParent()->getParent();

      RES_REPORT("-- " << F->getName().str() << "(), "
                       << F->getParent()->getModuleIdentifier() << "\n");
      RES_REPORT("   ");
      I->print(errs());
      RES_REPORT("\n");
    }
  }
  RES_REPORT("====== end printing leakerList ==========\n");

  RES_REPORT(
      "\n========= printing allocSyscallMap & leakSyscallMap ==========\n");
  cnt = 0;
  for (LeakerList::iterator i = Ctx->leakerList.begin(),
                            e = Ctx->leakerList.end();
       i != e; i++, cnt++) {

    std::string structName = i->first;
    RES_REPORT("[" << cnt << "] " << structName << "\n");

    // XXX
    // AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
    LeakSyscallMap::iterator lsit = Ctx->leakSyscallMap.find(structName);

    assert(
        // XXX
        //      asit != Ctx->allocSyscallMap.end() &&
        lsit != Ctx->leakSyscallMap.end() &&
        "leakerList is allocSyscallMap AND leakSyscallMap");

    // XXX
    /*
    RES_REPORT("<<<<<<<<<<<<<< Allocation <<<<<<<<<<<\n");

    for (auto F : asit->second)
        RES_REPORT(F->getName() << "\n");
    */

    RES_REPORT("<<<<<<<<<<<<<< Leaking <<<<<<<<<<<\n");

    for (auto F : lsit->second)
      RES_REPORT(F->getName() << "\n");

    RES_REPORT("\n");
  }
  RES_REPORT(
      "======== end printing allocSyscallMap & leakSyscallMap =======\n");
}
