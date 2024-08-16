function format_time(val) {if (val == null) {return "";} else {return new Date(val).format("yyyy-MM-dd HH:mm:ss");}}
function format_status(orderdetailState, totalWarehouseCount, totalReturnCount) {if (orderdetailState == 8 && totalWarehouseCount == 0) {return '拒绝收货';}if (orderdetailState == 8 && totalReturnCount > 0) {return '已退货';} return {"0":"已保存待提交","11":"已退货","1":"已提交待响应","2":"已响应待配送","3":"拒绝响应","4":"已配送待收货","5":"拒绝配送","6":"未及时配送","7":"收货中","8":"已收货","9":"已撤单","10":"拒绝收货"}[orderdetailState];}
function format_type(val) {return {"0":"普通订单","1":"补录订单","3":"临时订单","4":"备案订单","5":"带量订单"}[val];}
function export_data() {
	let datas = [['产品流水号', '目录名称', '医疗机构', '配送企业', '订单名称', '订单时间', '采购价格', '采购数量', '总配送数量', '总收货数量', '订单状态', '订单类型', '送货地址', '拒绝原因']];
	let r = /companyIdTb":"(.*?)"}/;
	let companyTb = r.exec(document.getElementsByTagName('iframe')[0].contentWindow.document.body.innerHTML);
	let companyIdTb = companyTb[1];
	let startTime = document.getElementsByTagName('iframe')[0].contentWindow.document.getElementById('submitStartTime').value;
	let endTime = document.getElementsByTagName('iframe')[0].contentWindow.document.getElementById('submitEndTime').value;
	let url = 'https://ggfw.scyb.org.cn/sjtrade/drugpurPurchaseOrderdetailRecent/getTBOrderByCompData.html?companyIdTb=' + companyIdTb + '&procurecatalogId=&productName=&hospitalNameStr=&companyNamePs=&orderNameStr=&submitStartTime=' + startTime + '&submitEndTime=' + endTime + '&orderdetailState=&_search=false&sidx=t.submit_time&sord=desc&rows=20&nd=';
	$.ajax({
		type: 'POST',
		url: url + new Date().getTime() + '&page=1',
		contentType: 'x-www-form-urlencoded',
		success: function(data) {
			let total = JSON.parse(data)['total'];
			for (let i=0;i<total;i++) {
				let page = i + 1;
				let post_url = url + new Date().getTime() + '&page=' + page;
				$.ajax({
					type: 'POST',
					async: false,
					url: post_url,
					contentType: 'x-www-form-urlencoded',
					success: function(d) {
						let rs = JSON.parse(d)['rows'];
						for(let j=0;j<rs.length; j++){
							let r = [rs[j]['procurecatalogId'], rs[j]['productName'], rs[j]['hospitalName'], rs[j]['companyNamePs'], rs[j]['orderName'], format_time(rs[j]['submitTime']), rs[j]['purchasePrice'], rs[j]['purchaseCount'], rs[j]['totalDistributeCount'], rs[j]['totalWarehouseCount'], format_status(rs[j]['orderdetailState'], rs[j]['totalWarehouseCount'], rs[j]['totalReturnCount']), format_type(rs[j]['orderType']), rs[j]['detailDistributeAddress'], rs[j]['refuseReason']];
							datas.push(r);
						}
					}
				})
			}
			let csv_data = "\uFEFF" + datas.map(row => row.join(",")).join("\n");
			let blob = new Blob([csv_data], {type: 'text/csv;charset=utf-8'});
			let link = document.createElement('a');
			link.style.display = 'none';
			link.href = URL.createObjectURL(blob);
			link.download = 'export.csv';
			document.body.appendChild(link);
			link.click();
			document.body.removeChild(link);
		}
	})
}

let e_b = document.createElement('button');e_b.innerText = '导出成 CSV 文件';e_b.classList.add('els-btn');e_b.classList.add('els-btn-blue');e_b.type = 'button';e_b.addEventListener('click', function() {export_data();});
document.getElementsByTagName('iframe')[0].contentWindow.document.getElementsByTagName('section')[0].getElementsByClassName('btn-control-box width-control')[0].appendChild(e_b);;
