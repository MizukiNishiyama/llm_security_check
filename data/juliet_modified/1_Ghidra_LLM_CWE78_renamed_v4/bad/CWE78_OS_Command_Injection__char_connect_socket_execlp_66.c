










void func_0(void)

{
  int iVar1;
  in_addr_t iVar2;
  int iVar3;
  size_t sVar4;
  ssize_t sVar5;
  char *pcVar6;
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
  sVar4 = _strlen(local_a4);
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
    local_b8.sa_data[0] = '\0';
    local_b8.sa_data[1] = '\0';
    local_b8.sa_data[2] = '\0';
    local_b8.sa_data[3] = '\0';
    local_b8.sa_data[4] = '\0';
    local_b8.sa_data[5] = '\0';
    iVar2 = _inet_addr("127.0.0.1");
    local_b8.sa_data._0_2_ = 0x8769;
    local_b8.sa_data._2_4_ = iVar2;
    iVar3 = _connect(iVar1,&local_b8,0x10);
    if (iVar3 != -1) {
      sVar5 = _recv(iVar1,local_a4 + sVar4,99 - sVar4,0);
      iVar3 = (int)sVar5;
      if ((iVar3 != -1) && (iVar3 != 0)) {
        local_a4[sVar4 + (ulong)(long)iVar3 / 1] = '\0';
        pcVar6 = _strchr(local_a4,0xd);
        if (pcVar6 != (char *)0x0) {
          *pcVar6 = '\0';
        }
        pcVar6 = _strchr(local_a4,10);
        if (pcVar6 != (char *)0x0) {
          *pcVar6 = '\0';
        }
      }
    }
  }
  if (iVar1 != -1) {
    _close(iVar1);
  }
  local_30 = local_a4;
  func_2(auStack_40);
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}