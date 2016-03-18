#!/usr/bin/sbcl --script

;; Despicable Name Server, version 0.1.

;; Copyright (c) 2016, Johann 'Myrkraverk' Oskarsson <johann@myrkraverk.com>
;; All rights reserved.

;; BSD 2-Clause License, see bottom of the file.

;; This little script implements the Despicable Name Server, for whom
;; all queries are "not implemented."  It does enough parsing of queries
;; to be a good starting point for a fully functional research DNS server.

;; It's based off of this little UDP tutorial:
;; https://gist.github.com/shortsightedsid/a760e0d83a9557aaffcc

;; Currently it does not have a good reply constructor, apart from the
;; header, but the one it has should be easily extensible.

;; Have you ever wanted to know if PostgreSQL would be a sane backend for
;; DNS queries?  Then grap Postmodern and give it a try.

;; Do you want to see if you can crash glibc, or use the CVE-2015-7547
;; vulnerability for remote code execution?  Then this just might be
;; the starting point you need.

;; The code has not been optimized, it is merely here to provide a
;; starting point for people to play with the DNS protocol.

;; Good luck and have fun.

;; We assume QuickLisp is loaded in ~/.sbclrc
(load #p"~/.sbclrc")

(ql:quickload :usocket)

(defun octets-to-word (buffer index)
  "Returns a 16 bit word, read from buffer at index and index + 1."

  ;; This could potentially benefit from bit manipulations directly.
  (+ (* 256 (aref buffer index))
     (aref buffer (1+ index))))

(defun reply-not-implemented (buffer id opcode)
  "Constructs a DNS reply into buffer, that means 'not implemented'.
Uses the ID to construct the first two bytes, the ID; and the OPCODE to
construct the opcode part of the reply.

Returns the size of the message, in the buffer."

  ;; This function is written to be easily extensible for different kinds of
  ;; DNS replies, hence there is some boilerplate that's strictly not necessary
  ;; for just "not implemented".

  ;; Replies start with the ID we got in the query.
  (replace buffer id :start1 0 :end1 2)

  (let ((qr 1) ;; 1 = response
	(aa 1) ;; We authoritively do not implement anything.
	(tc 0)
	(rd 0)
	(ra 0)
	(z 0)
	(ad 0)
	(cd 0)
	(rcode 4) ;; 4 = Not Implemented

	;; all counts are zero
	(qdcount 0)
	(ancount 0)
	(nscount 0)
	(arcount 0))

    (setf (aref buffer 2) (logior rd 
				  (ash tc 1) 
				  (ash aa 2) 
				  (ash opcode 3)
				  (ash qr 7)))
    (setf (aref buffer 3) (logior rcode 
				  (ash cd 4) 
				  (ash ad 5)
				  (ash z 6)
				  (ash ra 7)
				  ))
    (setf (aref buffer 4) (ash (logand qdcount #xff00) -8))
    (setf (aref buffer 5) (logand qdcount #xff))
    (setf (aref buffer 6) (ash (logand ancount #xff00) -8))
    (setf (aref buffer 7) (logand ancount #xff))
    (setf (aref buffer 8) (ash (logand nscount #xff00) -8))
    (setf (aref buffer 9) (logand nscount #xff))
    (setf (aref buffer 10) (ash (logand arcount #xff00) -8))
    (setf (aref buffer 11) (logand arcount #xff)))

  ;; We return the size of the DNS header, as there are no other fields.
  12)

(defun create-dns-server (host port buffer)
  (let* ((socket (usocket:socket-connect nil nil
					 :protocol :datagram
					 :element-type '(unsigned-byte 8)
					 :local-host host
					 :local-port port))
	 (send-buffer (make-array 512 :element-type '(unsigned-byte 8))))
    (unwind-protect
	(loop 
	  ;; On SBCL, usocket is a wrapper around sb-bsd-socket, which sets MSG_TRUNC when
	  ;; reading data from recvfrom().  This means additional data is discarded but
	  ;; the size returned is the actual datagram length.  This allows us to trivially
	  ;; ignore overlong datagram packets.
	  (multiple-value-bind (buffer size client receive-port)
	      ;; There may not be any need to supply a length here, since the buffer also
	      ;; has implied length, and both SBCL and usocket are documented to use that
	      ;; when length is nil.
	      (usocket:socket-receive socket buffer 512) ;; 512 is the maximum DNS query

	    ;; Maybe change that to check if the datagram was larger than our buffer.
	    ;; That'll make it easier to supply a larger buffer, later.
	    (when (<= size 512) ;; Overlong datagrams are simply ignored.
	      
	      ;; Parse all the bit fields in the DNS header.  This is hopefully correct.
	      ;; To understand whath these fields mean, refer to the appropriate RFCs.
	      (let ((id (subseq buffer 0 2))  ;; The id is kept as a subsequence.

		    ;; The flags and codes in the header are kepts as bits (0 or 1)
		    ;; or small (4 bit) integers.
		    (qr (ash (logand #x80 (aref buffer 2)) -7))
		    (opcode (ash (logand #x78 (aref buffer 2)) -3))
		    (aa (ash (logand #x04 (aref buffer 2)) -2))
		    (tc (ash (logand #x02 (aref buffer 2)) -1))
		    (rd (logand #x01 (aref buffer 2)))
		    (ra (ash (logand #x80 (aref buffer 3)) -7))
		    (z  (ash (logand #x40 (aref buffer 3)) -6))
		    (ad (ash (logand #x20 (aref buffer 3)) -5))
		    (cd (ash (logand #x10 (aref buffer 3)) -4))
		    (rcode (logand #x0f (aref buffer 3)))

		    ;; These counters are 16 bit numbers.
		    (qdcount (octets-to-word buffer 4))
		    (ancount (octets-to-word buffer 6))
		    (nscount (octets-to-word buffer 8))
		    (arcount (octets-to-word buffer 10)))
	      
		(let ((queries
		       (loop
			 ;; There are potentially more than one query in a DNS datagram.
			 ;; So we loop over all of them and collect a list of alists.
			 for query from 1 to qdcount
			 ;; We start with the index into the buffer at right past the
			 ;; header.
			 with index = 12
			 collect (loop ;; over the labels
				   ;; We grab the length of the first label; the list is
				   ;; terminated with a zero length, so we loop while the
				   ;; length is positive.
				   for length = (aref buffer index)
				   while (> length 0)
				   ;; We collect the ASCII format of the labels int a list
				   ;; poetically called `labels'.
				   collect (sb-ext:octets-to-string
					    (subseq buffer (1+ index) (+ 1 index length))
					    :external-format :ascii)
				   into labels
				   ;; Update the index into the buffer
				   do (setf index (+ 1 index length))
				   ;; Remember to update the index, so the outer loop remains
				   ;; correct, when we terminate.
				   finally (setf index (+ 4 index))
				   ;; And then return an alist of the form 
				   ;; ((:labels . labels) (:qtype . qtype) (:qclass . qclass))
				   finally (return (list (cons :labels labels)
							 (cons :qtype
							       (octets-to-word 
								buffer 
								;; negative reference because
								;; the former finally form
								;; points it past our query...
								(- index 3)))
							 (cons :qclass
							       (octets-to-word 
								buffer
								;; ...also here.
								(-  index 1)))))))))

		  ;; We do nothing with the queries, except print them to standard output.
		  (format t "~a~%" queries)
		      
		  ;; reply-not-implemented returns the size of the datagram, and 
		  ;; fills the buffer with the correct values as side effect.
		  (let ((reply-size (reply-not-implemented send-buffer id opcode)))
		    (usocket:socket-send socket
					 send-buffer
					 reply-size
					 :port receive-port
					 :host client)))))))

      ;; Because of the unwind-protect, we always close the socket; or
      ;; that's what we want.
      (usocket:socket-close socket))))
    
;; On Linux, to run this server as non-root, you may have to use
;; # setcap 'cap_net_bind_service=+ep' /usr/bin/sbcl
;; and give the SBCL binary root-port privileges.  This may, or may not
;; be OK, depending on your circumstances.
(create-dns-server "127.0.0.1" 53 
		   (make-array 512 :element-type '(unsigned-byte 8)))

;; -----------------------------------*----------------------------------- ;;

;; Copyright (c) 2016, Johann 'Myrkraverk' Oskarsson <johann@myrkraverk.com>
;; All rights reserved.

;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions
;; are met:

;; 1. Redistributions of source code must retain the above copyright
;; notice, this list of conditions and the following disclaimer.

;; 2. Redistributions in binary form must reproduce the above
;; copyright notice, this list of conditions and the following
;; disclaimer in the documentation and/or other materials provided
;; with the distribution.

;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
;; FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
;; COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
;; INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;; (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;; HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;; STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
;; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
;; OF THE POSSIBILITY OF SUCH DAMAGE.
