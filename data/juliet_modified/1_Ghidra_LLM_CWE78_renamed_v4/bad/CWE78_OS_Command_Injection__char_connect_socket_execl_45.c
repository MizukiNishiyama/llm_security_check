void func_0(void) {
  uint uVar1;
  in_addr_t iVar2;
  uint uVar3;
  size_t sVar4;
  char *pcVar5;
  int iVar6;
  sockaddr local_90;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  sVar4 = _strlen(local_7c);
  uVar1 = _socket(2,1,6);
  pcVar5 = (char *)(ulong)uVar1;
  if (uVar1 != 0xffffffff) {
    local_90.sa_data[6] = '\0';
    local_90.sa_data[7] = '\0';
    local_90.sa_data[8] = '\0';
    local_90.sa_data[9] = '\0';
    local_90.sa_data[10] = '\0';
    local_90.sa_data[0xb] = '\0';
    local_90.sa_data[0xc] = '\0';
    local_90.sa_data[0xd] = '\0';
    local_90.sa_len = '\0';
    local_90.sa_family = '\x02';
    local_90.sa_data[0] = '\0';
    local_90.sa_data[1] = '\0';
    local_90.sa_data[2] = '\0';
    local_90.sa_data[3] = '\0';
    local_90.sa_data[4] = '\0';
    local_90.sa_data[5] = '\0';
    iVar2 = _inet_addr("127.0.0.1");
    local_90.sa_data._0_2_ = 0x8769;
    local_90.sa_data._2_4_ = iVar2;
    uVar3 = _connect(uVar1,&local_90,0x10);
    pcVar5 = (char *)(ulong)uVar3;
    if (uVar3 != 0xffffffff) {
      pcVar5 = (char *)_recv(uVar1,local_7c + sVar4,99 - sVar4,0);
      iVar6 = (int)pcVar5;
      if ((iVar6 != -1) && (iVar6 != 0)) {
        local_7c[sVar4 + (ulong)(long)iVar6 / 1] = '\0';
        pcVar5 = _strchr(local_7c,0xd);
        if (pcVar5 != (char *)0x0) {
          *pcVar5 = '\0';
        }
        pcVar5 = _strchr(local_7c,10);
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
  DAT_100008000 = local_7c;
  func_2(pcVar5);
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}