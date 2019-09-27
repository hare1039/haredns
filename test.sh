l=(Google.com Youtube.com Tmall.com Baidu.com Qq.com Sohu.com Facebook.com Taobao.com Login.tmall.com Wikipedia.org Yahoo.com 360.cn Jd.com Amazon.com Sina.com.cn Weibo.com Live.com Pages.tmall.com Reddit.com Vk.com Netflix.com Blogspot.com Alipay.com Office.com Okezone.com)
#for i in ${l[@]}; do
#	sum=0
#	for j in {1..10}; do
#		sum=$(( $(./mydig $i A | grep Query | awk '{print $3}') + $sum ))
#	done;
#	echo "$i: $(( sum / 10))" 
#done

for i in ${l[@]}; do
	sum=0
	
	time for j in {1..10}; do
		sum=$(( $(dig $i +trace | grep Query | awk '{print $4}') + $sum ))
#		sum=$(( $(./mydig $i A | grep Query | awk '{print $3}') + $sum ))
	done;
	echo "$i: $(( sum / 10))" 
done
