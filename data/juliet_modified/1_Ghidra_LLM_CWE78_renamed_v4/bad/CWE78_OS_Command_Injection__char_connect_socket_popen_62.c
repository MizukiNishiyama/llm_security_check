void CWE78_OS_Command_Injection__char_connect_socket_popen_62::func_0(void)
{
  uint uVar1;
  FILE *pFVar2;
  char *local_88;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  local_88 = local_7c;
  func_2(&local_88);
  pFVar2 = _popen(local_88,"w");
  if (pFVar2 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar2);
    pFVar2 = (FILE *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(pFVar2);
  }
  return;
}