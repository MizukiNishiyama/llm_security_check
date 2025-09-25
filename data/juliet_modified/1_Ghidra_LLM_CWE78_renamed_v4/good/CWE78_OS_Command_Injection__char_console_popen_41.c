









FILE * func_5(char *param_1)

{
  uint uVar1;
  FILE *pFVar2;
  
  pFVar2 = _popen(param_1,"r");
  if (pFVar2 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar2);
    pFVar2 = (FILE *)(ulong)uVar1;
  }
  return pFVar2;
}