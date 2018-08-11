http_cookie_extract.so : http_cookie_extract.o
	gcc -g -Wall -shared -o http_cookie_extract.so http_cookie_extract.o
http_cookie_extract.o : Http_Cookie_Extract.c
	gcc -g -Wall -fPIC -c Http_Cookie_Extract.c -o http_cookie_extract.o
.PHONY : clean move
clean :
	rm http_cookie_extract.o http_cookie_extract.so
move :
	cp -rf  http_cookie_extract.so ../../
#/home/zhangshuai/sapp_run/plug/business/http_cookie_extract/
