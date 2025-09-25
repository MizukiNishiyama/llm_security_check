












void func_0(void)

{
  int iVar1;
  int iVar2;
  size_t sVar3;
  ssize_t sVar4;
  char *pcVar5;
  int local_d8;
  sockaddr local_a0;
  char local_8c [100];
  long local_28;
  
  local_28 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_8c,0,100);
  local_8c[0] = 'l';
  local_8c[1] = 0x73;
  local_8c[2] = 0x20;
  local_d8 = -1;
  sVar3 = _strlen(local_8c);
  iVar1 = _socket(2,1,6);
  if (iVar1 != -1) {
    local_a0.sa_data[6] = '\0';
    local_a0.sa_data[7] = '\0';
    local_a0.sa_data[8] = '\0';
    local_a0.sa_data[9] = '\0';
    local_a0.sa_data[10] = '\0';
    local_a0.sa_data[0xb] = '\0';
    local_a0.sa_data[0xc] = '\0';
    local_a0.sa_data[0xd] = '\0';
    local_a0.sa_len = '\0';
    local_a0.sa_family = '\x02';
    local_a0.sa_data[0] = 'i';
    local_a0.sa_data[1] = -0x79;
    local_a0.sa_data[2] = '\0';
    local_a0.sa_data[3] = '\0';
    local_a0.sa_data[4] = '\0';
    local_a0.sa_data[5] = '\0';
    iVar2 = _bind(iVar1,&local_a0,0x10);
    if (((iVar2 != -1) && (iVar2 = _listen(iVar1,5), iVar2 != -1)) &&
       (local_d8 = _accept(iVar1,(sockaddr *)0x0,(socklen_t *)0x0), local_d8 != -1)) {
      sVar4 = _recv(local_d8,local_8c + sVar3,99 - sVar3,0);
      iVar2 = (int)sVar4;
      if ((iVar2 != -1) && (iVar2 != 0)) {
        local_8c[sVar3 + (ulong)(long)iVar2 / 1] = '\0';
        pcVar5 = _strchr(local_8c,0xd);
        if (pcVar5 != (char *)0x0) {
          *pcVar5 = '\0';
        }
        pcVar5 = _strchr(local_8c,10);
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
  iVar1 = _execlp("sh","sh");
  if (*(long *)PTR____stack_chk_guard_100004000 != local_28) {
                    
    ___stack_chk_fail(iVar1);
  }
  return;
}