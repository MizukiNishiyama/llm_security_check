










void func_0(void)

{
  int iVar1;
  undefined1 local_7c;
  undefined1 local_7b;
  undefined1 local_7a;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(&local_7c,0,100);
  local_7c = 0x6c;
  local_7b = 0x73;
  local_7a = 0x20;
  func_2(&local_7c);
  iVar1 = _execlp("sh","sh");
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(iVar1);
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
  uint uVar1;
  in_addr_t iVar2;
  uint uVar3;
  size_t sVar4;
  char *pcVar5;
  int iVar6;
  sockaddr local_28;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  sVar4 = _strlen(param_1);
  uVar1 = _socket(2,1,6);
  pcVar5 = (char *)(ulong)uVar1;
  if (uVar1 != 0xffffffff) {
    local_28.sa_data[6] = '\0';
    local_28.sa_data[7] = '\0';
    local_28.sa_data[8] = '\0';
    local_28.sa_data[9] = '\0';
    local_28.sa_data[10] = '\0';
    local_28.sa_data[0xb] = '\0';
    local_28.sa_data[0xc] = '\0';
    local_28.sa_data[0xd] = '\0';
    local_28.sa_len = '\0';
    local_28.sa_family = '\x02';
    local_28.sa_data[0] = '\0';
    local_28.sa_data[1] = '\0';
    local_28.sa_data[2] = '\0';
    local_28.sa_data[3] = '\0';
    local_28.sa_data[4] = '\0';
    local_28.sa_data[5] = '\0';
    iVar2 = _inet_addr("127.0.0.1");
    local_28.sa_data._0_2_ = 0x8769;
    local_28.sa_data._2_4_ = iVar2;
    uVar3 = _connect(uVar1,&local_28,0x10);
    pcVar5 = (char *)(ulong)uVar3;
    if (uVar3 != 0xffffffff) {
      pcVar5 = (char *)_recv(uVar1,param_1 + sVar4,99 - sVar4,0);
      iVar6 = (int)pcVar5;
      if ((iVar6 != -1) && (iVar6 != 0)) {
        param_1[sVar4 + (ulong)(long)iVar6 / 1] = '\0';
        pcVar5 = _strchr(param_1,0xd);
        if (pcVar5 != (char *)0x0) {
          *pcVar5 = '\0';
        }
        pcVar5 = _strchr(param_1,10);
        if (pcVar5 != (char *)0x0) {
          *pcVar5 = '\0';
        }
      }
    }
  }
  if (uVar1 != 0xffffffff) {
    uVar1 = _close(uVar1);
    pcVar5 = (char *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(pcVar5);
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