










void func_0(void)

{
  int iVar1;
  int iVar2;
  size_t sVar3;
  ssize_t sVar4;
  char *pcVar5;
  int local_d8;
  sockaddr local_b8;
  char local_a4 [100];
  undefined1 auStack_40 [16];
  char *local_30;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_a4,0,100);
  local_a4[0] = 'l';
  local_a4[1] = 0x73;
  local_a4[2] = 0x20;
  local_d8 = -1;
  sVar3 = _strlen(local_a4);
  iVar1 = _socket(2,1,6);
  if (iVar1 != -1) {
    local_b8.sa_data[6] = '\0';
    local_b8.sa_data[7] = '\0';
    local_b8.sa_data[8] = '\0';
    local_b8.sa_data[9] = '\0';
    local_b8.sa_data[10] = '\0';
    local_b8.sa_data[0xb] = '\0';
    local_b8.sa_data[0xc] = '\0';
    local_b8.sa_data[0xd] = '\0';
    local_b8.sa_len = '\0';
    local_b8.sa_family = '\x02';
    local_b8.sa_data[0] = 'i';
    local_b8.sa_data[1] = -0x79;
    local_b8.sa_data[2] = '\0';
    local_b8.sa_data[3] = '\0';
    local_b8.sa_data[4] = '\0';
    local_b8.sa_data[5] = '\0';
    iVar2 = _bind(iVar1,&local_b8,0x10);
    if (((iVar2 != -1) && (iVar2 = _listen(iVar1,5), iVar2 != -1)) &&
       (local_d8 = _accept(iVar1,(sockaddr *)0x0,(socklen_t *)0x0), local_d8 != -1)) {
      sVar4 = _recv(local_d8,local_a4 + sVar3,99 - sVar3,0);
      iVar2 = (int)sVar4;
      if ((iVar2 != -1) && (iVar2 != 0)) {
        local_a4[sVar3 + (ulong)(long)iVar2 / 1] = '\0';
        pcVar5 = _strchr(local_a4,0xd);
        if (pcVar5 != (char *)0x0) {
          *pcVar5 = '\0';
        }
        pcVar5 = _strchr(local_a4,10);
        if (pcVar5 != (char *)0x0) {
          *pcVar5 = '\0';
        }
      }
    }
  }
  if (iVar1 != -1) {
    _close(iVar1);
  }
  if (local_d8 != -1) {
    _close(local_d8);
  }
  local_30 = local_a4;
  func_2(auStack_40);
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}