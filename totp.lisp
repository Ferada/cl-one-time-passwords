(in-package "CL-TOTP")

(defconstant .unix-epoch-zero. #.(encode-universal-time 0 0 0 1 1 1970 0))
  ;; 00:00:00 UTC on 1 January 1970

(defvar *time-zero* 0) ; aka the unix epoch zero
(defvar *time-step-in-seconds* 30)

(defmacro time-step (unix-time)
  `(floor (- ,unix-time *time-zero*) *time-step-in-seconds*))

(defun totp (key &optional (offset 0) (time (- (get-universal-time) .unix-epoch-zero. offset)))
  (hotp:hotp key (time-step time)))

(defun verify-totp (key token &key (range 0))
  (or (equal token (totp key))
      (loop
        for offset from 1 to range
        when (or (equal token (totp key (* offset *time-step-in-seconds*)))
                 (equal token (totp key (* (- offset) *time-step-in-seconds*))))
          return T)))
