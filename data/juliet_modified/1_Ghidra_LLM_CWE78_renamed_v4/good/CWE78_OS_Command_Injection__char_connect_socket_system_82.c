













void __thiscall
CWE78_OS_Command_Injection__char_connect_socket_system_82::
CWE78_OS_Command_Injection__char_connect_socket_system_82_goodG2B::action
          (CWE78_OS_Command_Injection__char_connect_socket_system_82_goodG2B *this,char *param_1)

{
  int iVar1;
  
  iVar1 = _system(param_1);
  if (iVar1 != 0) {
    func_6("command execution failed!");
                    
    _exit(1);
  }
  return;
}