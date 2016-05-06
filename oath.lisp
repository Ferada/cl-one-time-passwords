(in-package "CL-TOTP")

(defun make-otpauth-url (type label identity key-bytes issuer)
  (check-type type (member :hotp :totp))
  (format NIL "otpauth://~(~A~)/~@[~A:~]~A?secret=~A~@[&issuer=~A~]"
          type
          label
          identity
          (cl-base32:bytes-to-base32 key-bytes)
          issuer))

;; TODO: quri ogodmyeyesbleed can i please have a better parsing step here
(defun parse-otpauth-url (string)
  (multiple-value-bind (a b c d e f g)
      (quri:parse-uri string)
    (declare (ignore b g d))
    (assert (string-equal a "otpauth"))
    (assert (member c '("hotp" "totp") :test #'string-equal))
    (cl-ppcre:register-groups-bind (label identify) ("/(?:(.+):)?(.+)" e)
      (let ((params (quri.decode:url-decode-params f)))
        (values label
                identify
                (cl-base32:base32-to-bytes (cdr (assoc "secret" params :test #'string-equal)))
                (cdr (assoc "issuer" params :test #'string-equal)))))))

(defun generate-qr-code (output type label identity key-bytes issuer
                         &rest keys &key (if-exists :error) (if-does-not-exist :create) (format :png)
                         &allow-other-keys)
  (let ((text (make-otpauth-url type label identity key-bytes issuer)))
    (with-open-stream (stream (if (pathnamep output)
                                  (open output :direction :output :element-type '(unsigned-byte 8)
                                               :if-exists if-exists :if-does-not-exist if-does-not-exist)
                                  output))
      (ecase format
        (:png
         (apply #'cl-qrencode:encode-png-stream text stream :allow-other-keys T keys)))))
  (values))
