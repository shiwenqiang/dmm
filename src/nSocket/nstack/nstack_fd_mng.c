/*
*
* Copyright (c) 2018 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <math.h>
#include <string.h>

#include "nstack.h"
#include "nstack_fd_mng.h"
#include "nstack_socket.h"
#include "nstack_securec.h"
#include "nstack_sockops.h"

/* test_epollCtl_004_001_trial : both 32bit and 64bit members of 'ops' and 'conn'
   need to reset, otherwise it will be invalid address in 32bit APP case */
void
nstack_reset_fdInf (nstack_fd_Inf * fdInf)
{
  int loop;

  fdInf->isBound = NSTACK_FD_NOBIND;
  fdInf->rlfd = -1;
  fdInf->rmidx = -1;
  fdInf->nxtfd = -1;
  fdInf->fd = -1;
  fdInf->attr = 0;
  fdInf->ops = 0;               /*operations of the fd, for save space we user opIdx here */
  fdInf->type = 0;              /*the fd type like SOCK_STREAM|SOCK_NONBLOCK ... */

  NSTACK_SET_FD_BLOCKING (fdInf);
  for (loop = 0; loop < NSTACK_MAX_MODULE_NUM; loop++)
    {
      fdInf->protoFD[loop].fd = -1;
      fdInf->protoFD[loop].errCode = 0;
      fdInf->protoFD[loop].pad = 0;
      fdInf->protoFD[loop].liststate = NSTACK_NO_LISTENING;
    }

  nstack_reset_fd_local_lock_info (&(fdInf->local_lock));
  return;
}

nstack_fd_Inf *
nstack_fd2inf (int fd)
{
  /*if nstack init not finished, just return null */
  if (NSTACK_MODULE_SUCCESS != g_nStackInfo.fwInited)
    {
      return NULL;
    }
  if (nstack_is_nstack_sk (fd) && g_nStackInfo.lk_sockPoll)
    {
      return &(g_nStackInfo.lk_sockPoll[fd]);
    }
  return NULL;
}

void
nstack_set_protoFd (nstack_fd_Inf * fdInf, int modInx, int protofd)
{

  if (protofd < nstack_get_minfd_id (modInx)
      || protofd > nstack_get_maxfd_id (modInx))
    {
      NSSOC_LOGERR ("module:%d protofd invalid] protofd=%d", modInx, protofd);
      return;
    }
  /* Reviews: 设置fdInf中protoFD[modInx] */
  nstack_get_protoFd (fdInf, modInx) = protofd;
  /* Reviews: 设置epInf中protoFD[modInx] */
  nsep_set_infoProtoFD (fdInf->fd, modInx, protofd);

  nssct_create (fdInf->fd, protofd, modInx);
  return;
}

/* pass app info to struct netconn */
void
nstack_set_app_info (nstack_fd_Inf * fdInf, int modInx)
{
  return;
}

nstack_fd_Inf *
nstack_lk_fd_alloc_with_kernel (int nfd)
{
  nstack_fd_Inf *retInf = NULL;

  if ((nfd < 0) || (nfd >= (int) NSTACK_KERNEL_FD_MAX)
      || (!g_nStackInfo.lk_sockPoll))
    {
      NSSOC_LOGERR
        ("nfd < 0 or nfd>= NSTACK_KERNEL_FD_MAX, parameter not valid");
      return NULL;
    }
  /* SWQ-Reviews: 注意, 这里nfd是统一的由fix_mid(一般为linux_kernel)创建的fd */
  retInf = &g_nStackInfo.lk_sockPoll[nfd];

  if (FD_OPEN == retInf->local_lock.fd_status)
    {
      NSSOC_LOGERR ("nstack_lk_fd_alloc_with_kernel fd:%d already create",
                    nfd);
    }

  retInf->fd = nfd;
  /* SWQ-Reviews: 分配了epInfo, 并将其赋值给manager->infoSockMap[nfd] */
  if (-1 == nsep_alloc_infoWithSock (nfd))
    {
      NSSOC_LOGERR ("Can't alloc epInfo for nfd=%d]", nfd);
      nstack_reset_fdInf (retInf);
      return NULL;
    }
  /* SWQ-Reviews: 1. 设置fdInf->protoFD[fix_mid] = nfd;
                  2. 设置epInfo->protoFD[modInx] = nfd;
                  3. 设置g_select_fd_map.fdinf[fd].mod_fd[inx]=mfd, g_select_fd_map.modinf[inx].comm_fd[modfd] = cfd
                  注意:如果fd是一个epfd, 这里仍然需要给其注册到select_fd_map中,保证可以在select中对epfd的进行监听
  */
  nstack_set_protoFd (retInf, g_nstack_modules.fix_mid, nfd); // SWQ-Reviews: nstack_get_fix_mid()可以代替fix_mid
  NSSOC_LOGDBG ("nfd=%d,retInf_fd=%d", nfd, retInf->fd);
  return retInf;
}

int
nstack_fd_free_with_kernel (nstack_fd_Inf * fdInf)
{
  int closeRet = 0;
  ns_int32 fd;

  if (!fdInf)
    {
      NSSOC_LOGERR ("fdInf is NULL");
      return 0;
    }
  fd = fdInf->protoFD[nstack_get_fix_mid ()].fd;
  nstack_reset_fdInf (fdInf);

  if (fd >= 0 && fd < (int) NSTACK_KERNEL_FD_MAX)
    {
      NSTACK_CAL_FUN (nstack_fix_mid_ops (), close, (fd), closeRet);
      NSSOC_LOGINF ("close]fd=%d,ret=%d", fd, closeRet);
    }
  return closeRet;
}

void
nstack_fork_init_parent (pid_t ppid)
{
  int fd;
  nstack_fd_Inf *fdInf = NULL;
  for (fd = 0; fd < (int) NSTACK_KERNEL_FD_MAX; fd++)
    {
      fdInf = nstack_getValidInf (fd);
      if ((NULL != fdInf) && (!((u32_t) (fdInf->type) & SOCK_CLOEXEC)))
        {
          int i;
          nstack_each_modInx (i)
          {
            if ((nstack_extern_deal (i).fork_parent_fd)
                && (fdInf->protoFD[i].fd >= 0))
              {
                nstack_extern_deal (i).fork_parent_fd (fdInf->protoFD[i].fd,
                                                       ppid);
              }
          }
        }
    }
}

void
nstack_fork_init_child (pid_t ppid)
{
  pid_t cpid = update_sys_pid ();
  NSSOC_LOGDBG ("parent_pid=%d, child_pid=%d", ppid, cpid);

  nsfw_mgr_clr_fd_lock ();
  if (FALSE == nsfw_recycle_fork_init ())
    {
      NSFW_LOGERR ("init rec zone failed!]ppid=%d,cpid=%d", ppid, cpid);
    }

  int i;
  nstack_each_modInx (i)
  { /* Reviews: 只有lwip注册了回调接口sbr_fork_init_child */
    if (nstack_extern_deal (i).fork_init_child)
      {
        nstack_extern_deal (i).fork_init_child (ppid, cpid);
      }
  }

  int pos;
  nstack_fd_Inf *fdInf = NULL;

  for (pos = 0; pos < (int) NSTACK_KERNEL_FD_MAX; pos++)
    {
      fdInf = nstack_getValidInf (pos);
      if (fdInf)
        {
          if (!((u32_t) (fdInf->type) & SOCK_CLOEXEC))
            {
              nstack_fork_fd_local_lock_info (&fdInf->local_lock);

              nstack_each_modInx (i)
              {
                if ((nstack_extern_deal (i).fork_child_fd)
                    && (fdInf->protoFD[i].fd >= 0))
                  {
                    nstack_extern_deal (i).fork_child_fd (fdInf->
                                                          protoFD[i].fd, ppid,
                                                          cpid);
                  }
              }
            }
          else /* Reviews: 若置了CLOEXEC标志,调用fork_free_fd将无效epInfo 清除 */
            {
              nstack_reset_fd_local_lock_info (&fdInf->local_lock);
              nsep_set_infoSockMap (pos, NULL);
              nstack_each_modInx (i)
              {
                if ((nstack_extern_deal (i).fork_free_fd)
                    && (fdInf->protoFD[i].fd >= 0))
                  {
                    nstack_extern_deal (i).fork_free_fd (fdInf->protoFD[i].fd,
                                                         ppid, cpid);
                  }
              }
            }
        }
    }
}
