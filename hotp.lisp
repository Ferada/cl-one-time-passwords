(in-package "CL-HOTP")

; see: http://tools.ietf.org/html/rfc4226

(defvar *digits* 6)

(defvar *hmac-sha-mode* :sha1)

(defun ensure-key-bytes (object)
  (etypecase object
    (string (ironclad:hex-string-to-byte-array object))
    ((vector (unsigned-byte 8)) object)
    (vector (coerce object '(vector (unsigned-byte 8))))))

(defun hotp (key counter)
  (hotp-truncate (hmac-sha-n (ensure-key-bytes key) counter)))

(defun hotp-truncate (20-bytes)
  (flet ((dt (ht)
           (let* ((byte19 (aref ht 19))
                  (byte-offset (ldb (byte 4 0) byte19))
                  (result 0))
             (setf (ldb (byte 7 24) result) (aref ht byte-offset))
             (setf (ldb (byte 8 16) result) (aref ht (+ 1 byte-offset)))
             (setf (ldb (byte 8  8) result) (aref ht (+ 2 byte-offset)))
             (setf (ldb (byte 8  0) result) (aref ht (+ 3 byte-offset)))
             result)))
    (let ((sbits (dt 20-bytes)))
      (mod sbits
           (svref #(1 10 100 1000 10000 100000 1000000 10000000 100000000)
                  *digits*)))))

(defun hmac-sha-n (key counter)
  (loop
     with counter-bytes = (make-array 8 :element-type '(unsigned-byte 8))
     with hmac = (ironclad:make-hmac key *hmac-sha-mode*)
     finally
       (ironclad:update-hmac hmac counter-bytes)
       (return (ironclad:hmac-digest hmac))
     for i from 7 downto 0
     for offset from 0 by 8
     do (setf (aref counter-bytes i) (ldb (byte 8 offset) counter))))
