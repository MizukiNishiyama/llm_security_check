












int CWE78_OS_Command_Injection__char_connect_socket_execl_81::
    CWE78_OS_Command_Injection__char_connect_socket_execl_81_goodG2B::func_0(char *param_1)

{
  int iVar1;
  
  iVar1 = _execl("/bin/sh","/bin/sh");
  return iVar1;
}