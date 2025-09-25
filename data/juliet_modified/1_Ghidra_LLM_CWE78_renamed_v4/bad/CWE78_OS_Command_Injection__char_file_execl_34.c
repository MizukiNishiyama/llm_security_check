










void func_0(void)

{
  int iVar1;
  size_t sVar2;
  FILE *pFVar3;
  char *pcVar4;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  sVar2 = _strlen(local_7c);
  if ((1 < 100 - sVar2) && (pFVar3 = _fopen("/tmp/file.txt","r"), pFVar3 != (FILE *)0x0)) {
    pcVar4 = _fgets(local_7c + sVar2,100 - (int)sVar2,pFVar3);
    if (pcVar4 == (char *)0x0) {
      func_2("fgets() failed");
      local_7c[sVar2] = '\0';
    }
    _fclose(pFVar3);
  }
  iVar1 = _execl("/bin/sh","/bin/sh");
  if (*(long *)PTR____stack_chk_guard_100004000 == local_18) {
    return;
  }
                    
  ___stack_chk_fail(iVar1);
}







undefined4 func_1(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_2("Calling ...");
  func_0();
  func_2("Finished ");
  return 0;
}







ulong func_2(ulong param_1)

{
  uint uVar1;
  
  if (param_1 != 0) {
    uVar1 = _printf("%s\n");
    param_1 = (ulong)uVar1;
  }
  return param_1;
}




