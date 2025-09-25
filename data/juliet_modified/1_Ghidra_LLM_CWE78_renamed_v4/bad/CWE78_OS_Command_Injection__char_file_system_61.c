










void func_0(void)

{
  int iVar1;
  char *pcVar2;
  undefined1 local_7c;
  undefined1 local_7b;
  undefined1 local_7a;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(&local_7c,0,100);
  local_7c = 0x6c;
  local_7b = 0x73;
  local_7a = 0x20;
  pcVar2 = (char *)func_2(&local_7c);
  iVar1 = _system(pcVar2);
  if (iVar1 != 0) {
    func_3("command execution failed!");
                    
    _exit(1);
  }
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}







undefined4 func_1(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_3("Calling ...");
  func_0();
  func_3("Finished ");
  return 0;
}







char * func_2(char *param_1)

{
  size_t sVar1;
  FILE *pFVar2;
  char *pcVar3;
  
  sVar1 = _strlen(param_1);
  if ((1 < 100 - sVar1) && (pFVar2 = _fopen("/tmp/file.txt","r"), pFVar2 != (FILE *)0x0)) {
    pcVar3 = _fgets(param_1 + sVar1,100 - (int)sVar1,pFVar2);
    if (pcVar3 == (char *)0x0) {
      func_3("fgets() failed");
      param_1[sVar1] = '\0';
    }
    _fclose(pFVar2);
  }
  return param_1;
}







ulong func_3(ulong param_1)

{
  uint uVar1;
  
  if (param_1 != 0) {
    uVar1 = _printf("%s\n");
    param_1 = (ulong)uVar1;
  }
  return param_1;
}




