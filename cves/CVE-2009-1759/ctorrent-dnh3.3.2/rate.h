#ifndef RATE_H
#define RATE_H

#include "def.h"
#include <inttypes.h>
#include <sys/types.h>
#include <time.h>

typedef struct _bwsample{
  double timestamp;
  unsigned long bytes;
  struct _bwsample *next;
}BWSAMPLE;

class Rate{
 private:
  time_t m_last_timestamp;
  time_t m_total_timeused;
  uint64_t m_count_bytes;
  // m_last:    tracks recent xfer(s) for timing & limit comparison
  // m_recent:  the most recent measurable xfer
  // m_prev:    the prior m_recent
  double m_last_realtime, m_recent_realtime, m_prev_realtime;
  size_t m_last_size, m_recent_size, m_prev_size;
  double m_late;
  size_t m_nominal;
  time_t m_nom_time;
  struct{
    size_t value;
    time_t lasttime;
    double recent;
  } m_lastrate;

  unsigned char m_ontime:1;
  unsigned char m_update_nominal:1;
  unsigned char m_reserved:6;

  BWSAMPLE *m_history, *m_history_last;  // bandwidth history data

  Rate *m_selfrate;

  static BWSAMPLE *NewSample();

 public:
  Rate();

  void Reset();
  void StartTimer();
  void StopTimer();
  void ClearHistory();
  void Cleanup();
  void CountAdd(size_t nbytes);
  void UnCount(size_t nbytes);
  void RateAdd(size_t nbytes, size_t bwlimit);
  void RateAdd(size_t nbytes, size_t bwlimit, double timestamp);
  void operator=(const Rate &ra);
  uint64_t Count() const { return m_count_bytes; }
  size_t CurrentRate();
  size_t NominalRate();
  size_t RateMeasure();
  size_t RateMeasure(const Rate &ra);
  time_t TimeUsed();
  double LastRealtime() const { return m_last_realtime; }
  size_t LastSize() const { return m_last_size; }
  void SetSelf(Rate *rate) { m_selfrate = rate; }
  double Late() const { return m_late; }
  int Ontime() const { return m_ontime ? 1 : 0; }
  void Ontime(int yn) { m_ontime = yn ? 1 : 0; }
};

#endif
