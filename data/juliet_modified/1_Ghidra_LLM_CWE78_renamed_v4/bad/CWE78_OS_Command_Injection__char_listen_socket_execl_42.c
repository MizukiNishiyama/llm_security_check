










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
  func_1(&local_7c);
  iVar1 = _execl("/bin/sh","/bin/sh");
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(iVar1);
  }
  return;
}







char * func_1(char *param_1)

{
  uint uVar1;
  uint uVar2;
  size_t sVar3;
  char *pcVar4;
  int iVar5;
  uint local_48;
  sockaddr local_28;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  local_48 = 0xffffffff;
  sVar3 = _strlen(param_1);
  uVar1 = _socket(2,1,6);
  pcVar4 = (char *)(ulong)uVar1;
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
    local_28.sa_data[0] = 'i';
    local_28.sa_data[1] = -0x79;
    local_28.sa_data[2] = '\0';
    local_28.sa_data[3] = '\0';
    local_28.sa_data[4] = '\0';
    local_28.sa_data[5] = '\0';
    uVar2 = _bind(uVar1,&local_28,0x10);
    pcVar4 = (char *)(ulong)uVar2;
    if (uVar2 != 0xffffffff) {
      uVar2 = _listen(uVar1,5);
      pcVar4 = (char *)(ulong)uVar2;
      if (uVar2 != 0xffffffff) {
        local_48 = _accept(uVar1,(sockaddr *)0x0,(socklen_t *)0x0);
        pcVar4 = (char *)(ulong)local_48;
        if (local_48 != 0xffffffff) {
          pcVar4 = (char *)_recv(local_48,param_1 + sVar3,99 - sVar3,0);
          iVar5 = (int)pcVar4;
          if ((iVar5 != -1) && (iVar5 != 0)) {
            param_1[sVar3 + (ulong)(long)iVar5 / 1] = '\0';
            pcVar4 = _strchr(param_1,0xd);
            if (pcVar4 != (char *)0x0) {
              *pcVar4 = '\0';
            }
            pcVar4 = _strchr(param_1,10);
            if (pcVar4 != (char *)0x0) {
              *pcVar4 = '\0';
            }
          }
        }
      }
    }
  }
  if (uVar1 != 0xffffffff) {
    uVar1 = _close(uVar1);
    pcVar4 = (char *)(ulong)uVar1;
  }
  if (local_48 != 0xffffffff) {
    uVar1 = _close(local_48);
    pcVar4 = (char *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(pcVar4);
  }
  return param_1;
}







undefined4 func_2(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_3("Calling ...");
  func_0();
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




