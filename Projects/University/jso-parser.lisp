; 822387 Biondi Simone

;define macro name
(defmacro as (list &rest body) (append (list 'lambda list) body))   ;associa
(defmacro -> (list &rest body) (append (list 'lambda list) body))
(defmacro @ (&rest args) (cons 'funcall args))

;lambda function
(set' mark
    (-> (stream yes no)
        (@ yes stream stream)))

(defun recall (position)
    (-> (stream yes no)
        (@ yes nil position)))
 
;Prende in input una stringa e la converto in stream 
(defun string->stream (string)
    (coerce string 'list))
;Prende in input uno stream e la converto in stringa per valutarlo
(defun stream->string (stream)
    (coerce stream 'string))

(defun startswith (part list)
    (cond
        ((and (null part) (null list))
            t)

        ((null part)
            t)

        ((null list)
            nil)

        ((eq (car part) (car list))
            (startswith (cdr part) (cdr list))
        )
    )) 

(defun drop (part list)
    (cond
        ((null part)
            list)

        ((null list)
            nil)

        (t
            (drop (cdr part) (cdr list)))))

(set' uncons 
    (-> (stream yes no)
        (cond
            ((null stream) (@ no "not the end of stream" stream))
            (t             (@ yes (first stream) (rest stream)))
        )))

; Metodo principale del parser
; prende in input uno stream, lo converte in char e valuta se è in formato object o array
(defun json-parse (stream)
    (json-parse-aux json stream))

(defun just (value)
    (-> (stream yes no)
        (@ yes value stream)))

(defun expected (what)
    (-> (stream yes no)
        (@ no what stream)))

(defun with (parser callback)
    (-> (stream yes no)
        (@ parser 
            stream 
            (-> (result rest)
                (@ (@ callback result) rest yes no))
            no)))

(defun after (parser another)
    (with parser (as (unused)
          another)))

(defun fallback (parser fallback)
    (-> (stream yes no)
        (@ parser 
            stream 
            yes
            (-> (err rest)
                (@ (@ fallback err) rest yes no)))))

(defun or-else (parser another)
    (fallback parser (as (unused)
              another)))

(defun is-string (token)
    (-> (stream yes no)
        (let ((list (string->stream token)))
        (if (startswith list stream)
            (@ yes token (drop list stream))
            (@ no  token            stream)))))

(defun satisfying (description predicate)
    (with mark   (as (here)
    (with uncons (as (char)
          (if (@ predicate char)
              (just char)
              (after (recall here) 
                     (expected description))))))))

(defun zero-or-more (parser)
    (or-else (one-or-more parser)
             (just nil)))

; Una stringa ha n caratteri
(defun one-or-more (parser)
    (with  parser               (as (x)
    (with (zero-or-more parser) (as (xs)
          (just (cons x xs)))))))

(defun sep-by (separator parser)
    (or-else (sep-by-1 separator parser)
             (just nil)))

(defun sep-by-1 (separator parser)
    (with parser                                  (as (first)
    (with (zero-or-more (after separator parser)) (as (rest)
          (just (cons first rest)))))))

; Elimina spazi
(defun is-space (char)
    (member char (list #\Space #\Tab #\NewLine)))

(set 'spaces 
    (zero-or-more 
        (satisfying "space" #'is-space)))

; JSON è una sequenza di token
; questo metodo valuta se è formato json
(defun token (token)
    (with  (is-string token) (as (result)
    (after  spaces           
           (just result)))))

(defun one-of (string)
    (let ((list (string->stream string)))
        (-> (char)
            (member char list))))

(defun any (description &rest parsers)
    (any-raw description parsers))

(defun any-raw (description parsers)
    (if (null parsers)
        (expected description)
        (or-else (first parsers)
                 (any-raw description (rest parsers)))))

(defun recursion-point (quoted-parser)
    (-> (stream yes no)
        (@ (eval quoted-parser) stream yes no)))

(defun just-wrapped (name item)
    (just (cons name item)))

; json value può essere number,string, array o object
(set 'json 
    (recursion-point
        '(any "json-value"
            json-number
            json-string
            json-array
            json-obj)))

; parsa json char
; (controllo apici)
(set 'json-char
    (any "json-char"
        (after (is-string "\\\"")
               (just #\"))

        (satisfying "non-dquote-char" 
            (-> (c) (char/= c #\")))))

; parsa json number

(set 'json-number
    (let ((json-number-text
            (one-or-more 
                (satisfying "number" 
                    (one-of "1234567890.-")))))
    
        (with  json-number-text (as (text)
        (after spaces
              (just (with-input-from-string (in (stream->string text))(read in))))))))

; parsa stringa 
(set 'json-string
    (or (after (is-string "\"")
    (with  (zero-or-more json-char) (as (content)
    (after (is-string "\"")
    (after  spaces
           (just (stream->string content)))))))
    (after (is-string "\'")
    (with  (zero-or-more json-char) (as (content)
    (after (is-string "\'")
    (after  spaces
           (just (stream->string content))))))))
)

; json array
(set' json-array
    (after spaces
    (after (token "[")
    (with  (sep-by (token ",") json) (as (items)
    (after spaces
    (after (token "]")
    (after  spaces
           (just-wrapped 'json-array items)))))))))

; pair("name : value");
(set' json-pair
    (with   json-string (as (name)
    (after (token ":")
    (with   json        (as (value)
    (after  spaces
           (just (list name value)))))))))

; json object
(set' json-obj
    (after spaces
    (after (token "{")
    (with (sep-by (token ",") json-pair) (as (fields)
    (after spaces
    (after (token "}")
    (after  spaces
           (just-wrapped 'json-obj fields)))))))))


(defun json-parse-aux (parser stream)
    (@ parser 
        (string->stream stream)
        (-> (result at) result)
        (-> (err    at) (error (format nil "~S: ~S" err (stream->string at))))))

(defun nth-item (n list)
    (cond 
        ((null list)
            (error "index out of diapasone"))

        ((= 0 n)
            (car list))

        (t
            (nth-item (1- n) (cdr list)))
    ))

(defun find-key (key map)
    (cond
        ((null map)
            (error "no key"))

        ((equal key (caar map))
            (cadar map))

        (t
            (find-key key (cdr map)))
    ))

(defun json-dot-aux (json path)
    (cond
        ((null path)
            json)

        ((eq (car json) 'json-array)
            (json-dot-aux 
                (nth-item (first path) (rest json))
                (rest path)))

        ((eq (car json) 'json-obj)
            (json-dot-aux 
                (find-key (first path) (rest json))
                (rest path)))

        ; access into numbers or string is prohibited
        (t
            (error "error"))
    ))

; Dato un oggetto e un elemento-key, ritorna elemento-value
(defun json-get (json &rest path)
    (json-dot-aux json path))

; Chiamo il parser su un file json
(defun json-load (filename)
  (with-open-file (stream filename)
    (let ((contents (make-string (file-length stream))))
       (read-sequence contents stream)
       (json-parse contents))))

;-------------------------------------------------------------------------------------------------------
(defun remove-last-comma (JSON)
  (cond
    ((string= "" JSON) JSON)
    (T (subseq JSON 0 (- (length JSON) 1)))))


(defun json-to-string (JSON)
  (cond
   ((eq (car JSON) 'JSON-OBJ) (concatenate 'string 
                                           "{" 
                                            (funcall 'remove-last-comma
                                                    (json-print-obj (cdr JSON))) 
                                           "}"
                                           ))
   ((eq (car JSON) 'json-array) (concatenate 'string 
                                             "[" 
                                             (funcall 'remove-last-comma
                                                      (json-print-array (cdr JSON)))
                                             "]"
                                             ))
   (T (error "Syntax-error"))))

(defun json-write (JSON filename)
   (with-open-file (stream filename 
                    :direction :output 
                    :if-exists :supersede
                    :if-does-not-exist :create)
   (format stream (funcall 'json-to-string JSON))))

(defun json-print-obj (JSON)
   (cond
      ((NULL JSON) "") ((listp (car JSON)) 
      (concatenate 'string 
                   (json-print-pair (car JSON)) (json-print-obj (cdr JSON))))))


(defun json-print-pair (JSON)
  (concatenate 'string "\""
               (car JSON)
               "\"" ":" 
               (json-print-value (car (cdr JSON)))
               ","
               ))

(defun json-print-value (JSON)
  (cond
   ((numberp JSON) (write-to-string JSON))
   ((stringp JSON) (concatenate 'string "\"" JSON "\""))
   (T (json-to-string JSON))))

(defun json-print-array (JSON)
  (cond
   ((NULL JSON) "")
   (T (concatenate 'string 
      (json-print-value (car JSON))
       ","
      (json-print-array (cdr JSON))
    ))))
