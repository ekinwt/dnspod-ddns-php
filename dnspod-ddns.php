<?php
/*
 * 使用 DNSPod api 实现动态域名
 * http://www.greatsu.cn
 *
 * Copyright 2011-2015, Ekin Su, ekinwt@gmail.com
 *
 * 需要服务器支持 CURL
 * 使用前，需配置好页面前部的 $dnspod_data 配置项[login_token, domain, record_name, record_line]
 * 将配置好的页面上传致服务器，然后访问它，即可将 DNSPod 中相应的记录修改为访问客户端的 IP
 * 比如：宽带没有固定 IP，只需使用在当前 IP 下的任何设备访问配置的页面，即可自动修改 DNSPod 的记录值，达到动态域名的目的
 *
 */

define("DEBUG", false);

if (DEBUG) {
	ini_set("display_errors", true);
	error_reporting(E_ALL);
}

// DNSPod api 地址
$api_base = "https://dnsapi.cn/";

// 配置项
$dnspod_data = array();

// 帐号密码的方式在 DnsPod 中已不支持，请使用 Token 方式登录
//$dnspod_data["user"] = "dnspod account";		// dnspod 帐号
//$dnspod_data["password"] = "dnspod password";			// dnspod 密码

$dnspod_data["login_token"] = "DNSPod login token";		// 在 DNSPod 生成
$dnspod_data["domain"] = "domain.com";		// 域名，不包含子名域, 例：greatsu.cn
$dnspod_data["record_name"] = "www";			// 记录（子域名），如: www
$dnspod_data["record_line"] = "默认";			// 解析线路，一般为默认

/*
 * -------------------------------------
 * 以下为 DNSPod 操作函数
 * -------------------------------------
 */

function get_dnspod_info() {
	global $dnspod_data;

	// 获得域名 id
	$api = "Domain.List";
	$data = build_call_base_data();

	$response = call_api($api, $data);
	$domain_array = $response["domains"];

	$domain_id = false;
	foreach ($domain_array as $domain) {
		if ($domain["name"] == $dnspod_data["domain"]) {
			$domain_id = $domain["id"];
			break;
		}
	}

	if ($domain_id === false) {
		exit_with_message("错误：找不到对应的域名");
	}

	// 获得记录 id
	$api = "Record.List";
	$data = build_call_base_data();
	$data = array_merge($data, array("domain_id" => $domain_id));

	$response = call_api($api, $data);
	$records_array = $response["records"];

	$record_id = false;
	$record_value = "";
	foreach ($records_array as $record) {
		if ($record["name"] == $dnspod_data["record_name"]) {
			$record_id = $record["id"];
			$record_value = $record["value"];
			break;
		}
	}

	if ($record_id === false) {
		exit_with_message("错误：找不到对应的记录");
	}

	$dnspod_info = array();
	$dnspod_info["domain_id"] = $domain_id;
	$dnspod_info["record_id"] = $record_id;
	$dnspod_info["record_value"] = $record_value;

	return $dnspod_info;
}

function refresh_dnspod($new_ip, $dnspod_info) {
	global $dnspod_data;

	$api = "Record.Ddns";
	$data = build_call_base_data();
	$data = array_merge($data, array("domain_id" => $dnspod_info["domain_id"], "record_id" => $dnspod_info["record_id"], "sub_domain" => $dnspod_data["record_name"], "record_line" => $dnspod_data["record_line"], "value" => $new_ip));

	$response = call_api($api, $data);
	$record = $response["record"];

	$message = "{$dnspod_data["record_name"]}.{$dnspod_data["domain"]}已更新为{$record["value"]}";
	exit($message);
}

/*
 * -------------------------------------
 * 以下为基础公共函数
 * -------------------------------------
 */

function build_call_base_data() {
	global $dnspod_data;

	//$data = array("login_email" => $dnspod_data["user"], "login_password" => $dnspod_data["password"], "format" => "json", "lang" => "cn", "error_on_empty" => "no");
	$data = array("login_token" => $dnspod_data["login_token"], "format" => "json", "lang" => "cn", "error_on_empty" => "no");
	return $data;
}

function call_api($api, $data) {
	global $api_base;

	if ($api == "" || !is_array($data)) {
            exit_with_message("错误：参数错误");
        }

        $api = $api_base . $api;

        $response = post_data($api, $data);
        if (!$response) {
            exit_with_message("错误：调用失败");
        }

        $response = explode("\r\n\r\n", $response);

        $results = @json_decode($response[1], 1);
        if (!is_array($results)) {
            exit_with_message("错误：返回异常");
        }

        if ($results["status"]["code"] != 1 && $results["status"]["code"] != 50) {
            exit_with_message($results["status"]["message"]);
        }

        return $results;
}

function get_client_ip() {
	$ip_address = "";

	if (isset($_SERVER["HTTP_CLIENT_IP"]) && $_SERVER["HTTP_CLIENT_IP"]) {
		$ip_address = $_SERVER["HTTP_CLIENT_IP"];
	}
	else if(isset($_SERVER["HTTP_X_FORWARDED_FOR"]) && $_SERVER["HTTP_X_FORWARDED_FOR"]) {
		$ip_address = $_SERVER["HTTP_X_FORWARDED_FOR"];
	}
	else if(isset($_SERVER["HTTP_X_FORWARDED"]) && $_SERVER["HTTP_X_FORWARDED"]) {
		$ip_address = $_SERVER["HTTP_X_FORWARDED"];
	}
	else if(isset($_SERVER["HTTP_FORWARDED_FOR"]) && $_SERVER["HTTP_FORWARDED_FOR"]) {
		$ip_address = $_SERVER["HTTP_FORWARDED_FOR"];
	}
	else if(isset($_SERVER["HTTP_FORWARDED"]) && $_SERVER["HTTP_FORWARDED"]) {
		$ip_address = $_SERVER["HTTP_FORWARDED"];
	}
	else if(isset($_SERVER["REMOTE_ADDR"]) && $_SERVER["REMOTE_ADDR"]) {
		$ip_address = $_SERVER["REMOTE_ADDR"];
	}
	else {
		$ip_address = "UNKNOWN";
	}

	return $ip_address;
}

function post_data($url, $data) {
    if ($url == "" || !is_array($data)) {
        exit_with_message("错误：参数错误");
    }

    $ch = @curl_init();
    if (!$ch) {
        exit_with_message("错误：服务器不支持CURL");
    }

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_SSLVERSION, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_USERAGENT, "DNSPod DDNS PHP Web Client/1.0.0, By ekinwt");
    $result = curl_exec($ch);
    curl_close($ch);

    return $result;
}

function exit_with_message($message) {
	exit($message);
}

/*
 * -------------------------------------
 * 开始刷新
 * -------------------------------------
 */

function start_refresh() {
	$client_ip = get_client_ip();
	$dnspod_info = get_dnspod_info();

	// 检查记录是否需要更新
	if ($dnspod_info["record_value"] == $client_ip) {
		exit_with_message("记录已为最新值，无需更新");
	}

	refresh_dnspod($client_ip, $dnspod_info);
}

start_refresh();

?>
