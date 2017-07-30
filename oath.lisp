(in-package "CL-TOTP")

(defun make-otpauth-url (type label identity key-bytes &key issuer (algorithm :sha1) (digits 6) (period 30))
  (check-type type (member :hotp :totp))
  (format NIL "otpauth://~(~A~)/~@[~A:~]~A?secret=~A~@[&issuer=~A~]~@[&algorithm=~A~]~@[&digits=~D~]~@[&period=~D~]"
          type
          label
          identity
          (cl-base32:bytes-to-base32 key-bytes)
          issuer
          algorithm
          digits
          period))

;; TODO: quri ogodmyeyesbleed can i please have a better parsing step here
(defun parse-otpauth-url (string)
  (multiple-value-bind (a b c d e f g)
      (quri:parse-uri string)
    (declare (ignore b g d))
    (assert (string-equal a "otpauth"))
    (assert (member c '("hotp" "totp") :test #'string-equal))
    (cl-ppcre:register-groups-bind (label identify) ("/(?:(.+):)?(.+)" e)
      (let ((params (quri.decode:url-decode-params f)))
        (flet ((param (name)
                 (cdr (assoc name params :test #'string-equal))))
          (values label
                  identify
                  (cl-base32:base32-to-bytes (param "secret"))
                  (param "issuer")
                  (let ((algorithm (param "algorithm")))
                    (and algorithm (cond
                                     ((string-equal algorithm "SHA1") :sha1)
                                     (T (warn "Unknown algorithm ~A." algorithm) algorithm))))
                  (let ((digits (param "digits")))
                    (and digits (parse-integer digits)))
                  (let ((period (param "period")))
                    (and period (parse-integer period)))))))))

(defun generate-qr-code (output type label identity key-bytes
                         &rest keys &key issuer (if-exists :error) (if-does-not-exist :create) (format :png)
                         &allow-other-keys)
  (let ((text (apply #'make-otpauth-url type label identity key-bytes :allow-other-keys T keys)))
    (with-open-stream (stream (if (pathnamep output)
                                  (open output :direction :output :element-type '(unsigned-byte 8)
                                               :if-exists if-exists :if-does-not-exist if-does-not-exist)
                                  output))
      (ecase format
        (:png
         (apply #'cl-qrencode:encode-png-stream text stream :allow-other-keys T keys)))))
  (values))
