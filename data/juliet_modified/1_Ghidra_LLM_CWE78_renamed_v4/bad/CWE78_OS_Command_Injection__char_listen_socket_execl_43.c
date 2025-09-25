void CWE78_OS_Command_Injection__char_listen_socket_execl_43::func_0(void)

{
  int iVar1;
  undefined1 *local_88;
  undefined1 local_7c;
  undefined1 local_7b;
  undefined1 local_7a;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(&local_7c,0,100);
  local_7c = 0x6c;
  local_7b = 0x73;
  local_7a = 0x20;
  local_88 = &local_7c;
  func_1(&local_88);
  iVar1 = _execl("/bin/sh","/bin/sh");
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(iVar1);
  }
  return;
}