












CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B * __thiscall
CWE78_OS_Command_Injection__char_console_execlp_84::
CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B::
CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B
          (CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B *this,char *param_1)

{
  *(char **)this = param_1;
  _strcat(*(char **)this,"*.*");
  return this;
}










CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B * __thiscall
CWE78_OS_Command_Injection__char_console_execlp_84::
CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B::
CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B
          (CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B *this,char *param_1)

{
  CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B(this,param_1);
  return this;
}










CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B * __thiscall
CWE78_OS_Command_Injection__char_console_execlp_84::
CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B::
~CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B
          (CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B *this)

{
  _execlp("sh","sh");
  return this;
}










CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B * __thiscall
CWE78_OS_Command_Injection__char_console_execlp_84::
CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B::
~CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B
          (CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B *this)

{
  ~CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B(this);
  return this;
}









void CWE78_OS_Command_Injection__char_console_execlp_84::func_0(void)

{
  func_1();
  return;
}







void func_1(void)

{
  CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B *this;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004018;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  this = (CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B *)operator_new(8);
  CWE78_OS_Command_Injection__char_console_execlp_84::
  CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B::
  CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B(this,local_7c);
  if (this != (CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B *)0x0) {
    CWE78_OS_Command_Injection__char_console_execlp_84::
    CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B::
    ~CWE78_OS_Command_Injection__char_console_execlp_84_goodG2B(this);
    operator_delete(this);
  }
  if (*(long *)PTR____stack_chk_guard_100004018 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}







undefined4 func_2(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_3("Calling ...");
  CWE78_OS_Command_Injection__char_console_execlp_84::func_0();
  func_3("Finished ");
  return 0;
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