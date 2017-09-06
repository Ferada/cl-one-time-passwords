(in-package "CL-TOTP")

(defconstant .unix-epoch-zero. 2208988800)
  ;; 00:00:00 UTC on 1 January 1970
  ;; (encode-universal-time 0 0 0 1 1 1970 0)
  ;; --> 2208988800

(defvar *time-zero* 0) ; aka the unix epoch zero
(defvar *time-step-in-seconds* 30)

(defmacro time-step (unix-time)
  `(floor (- ,unix-time *time-zero*) *time-step-in-seconds*))

(defun totp (key &optional (offset 0) (time (- (get-universal-time) .unix-epoch-zero. offset)))
  (hotp:hotp key (time-step time)))
