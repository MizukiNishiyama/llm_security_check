












void CWE78_OS_Command_Injection__char_file_system_62::func_0(void)

{
  int iVar1;
  char *local_88;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  local_88 = local_7c;
  badSource(&local_88);
  iVar1 = _system(local_88);
  if (iVar1 != 0) {
    func_2("command execution failed!");
                    
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
  func_2("Calling ...");
  CWE78_OS_Command_Injection__char_file_system_62::func_0();
  func_2("Finished ");
  return 0;
}









FILE * CWE78_OS_Command_Injection__char_file_system_62::badSource(char **param_1)

{
  uint uVar1;
  FILE *pFVar2;
  FILE *pFVar3;
  char *pcVar4;
  
  pFVar2 = (FILE *)_strlen(*param_1);
  pFVar3 = pFVar2;
  if ((1 < 100U - (long)pFVar2) && (pFVar3 = _fopen("/tmp/file.txt","r"), pFVar3 != (FILE *)0x0)) {
    pcVar4 = _fgets(*param_1 + (long)pFVar2,100 - (int)pFVar2,pFVar3);
    if (pcVar4 == (char *)0x0) {
      func_2("fgets() failed");
      (*param_1)[(long)pFVar2] = '\0';
    }
    uVar1 = _fclose(pFVar3);
    pFVar3 = (FILE *)(ulong)uVar1;
  }
  return pFVar3;
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