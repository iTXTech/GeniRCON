<?php

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GeniRCON Client
 *
 * GeniRCON is based on Source_RCON_PROTOCOL.
 * GeniRCON allows you to access server consolo through GeniRCON Client (not just running commands!)
 * Servers using GeniRCON can also use RCON to connect.
 *
 * ConsoleDaemon is based on CommandReader from PocketMine-MP.
 * Terminal, TextFormat, MainLogger are copied from PocketMine-MP.
 * Class GeniRCON is based on Chris Churchwell's Rcon.
 *
 * @author PeratX
 * @link https://github.com/iTXTech/GeniRCON
 *
 */

class ConsoleDaemon extends Thread{
	private $readline;
	/** @var \Threaded */
	protected $buffer;
	private $shutdown = false;

	public function __construct(){
		$this->buffer = new \Threaded;
		$this->start();
	}

	public function shutdown(){
		$this->shutdown = true;
	}

	private function readLine(){
		if(!$this->readline){
			global $stdin;

			if(!is_resource($stdin)){
				return "";
			}

			return trim(fgets($stdin));
		}else{
			$line = trim(readline("> "));
			if($line != ""){
				readline_add_history($line);
			}

			return $line;
		}
	}

	/**
	 * Reads a line from console, if available. Returns null if not available
	 *
	 * @return string|null
	 */
	public function getLine(){
		if($this->buffer->count() !== 0){
			return $this->buffer->shift();
		}

		return null;
	}

	public function quit(){
		$this->shutdown();
	}

	public function run(){
		$opts = getopt("", ["disable-readline"]);
		if(extension_loaded("readline") and !isset($opts["disable-readline"])){
			$this->readline = true;
		}else{
			global $stdin;
			$stdin = fopen("php://stdin", "r");
			stream_set_blocking($stdin, 0);
			$this->readline = false;
		}

		$lastLine = microtime(true);
		while(!$this->shutdown){
			if(($line = $this->readLine()) !== ""){
				$this->buffer[] = preg_replace("#\\x1b\\x5b([^\\x1b]*\\x7e|[\\x40-\\x50])#", "", $line);
			}elseif(!$this->shutdown and (microtime(true) - $lastLine) <= 0.1){ //Non blocking! Sleep to save CPU
				$this->synchronized(function(){
					$this->wait(10000);
				});
			}

			$lastLine = microtime(true);
		}
	}
}

class GeniRCON{

	private $host;
	private $port;
	private $password;
	private $timeout;

	private $socket;

	private $authorized;
	private $lastResponse = null;

	const PROTOCOL_VERSION = 2;

	const PACKET_AUTHORIZE = 5;
	const PACKET_COMMAND = 6;
	const PACKET_LOGGER = 7;
	const PACKET_PROTOCOL_CHECK = 8;

	const SERVERDATA_AUTH = 3;
	const SERVERDATA_AUTH_RESPONSE = 2;
	const SERVERDATA_EXECCOMMAND = 2;
	const SERVERDATA_RESPONSE_VALUE = 0;
	const SERVERDATA_LOGGER = 4;
	const SERVERDATA_PROTOCOL = 9;

	/** @var MainLogger */
	private $logger;

	public function __construct(MainLogger $logger, $host, $port, $password, $timeout){
		$this->logger = $logger;
		$this->host = $host;
		$this->port = $port;
		$this->password = $password;
		$this->timeout = $timeout;

	}

	public function getResponse(){
		$res = $this->lastResponse;
		$this->lastResponse = null;
		return $res;
	}

	public function connect(){

		$this->socket = fsockopen($this->host, $this->port, $errno, $errstr, $this->timeout);

		if(!$this->socket){
			$this->lastResponse = $errstr;
			return false;
		}

		//set timeout
		stream_set_timeout($this->socket, 3, 0);

		//authorize
		$auth = $this->authorize();

		if($auth){
			$protocol = $this->getRemoteProtocol();
			if($protocol != self::PROTOCOL_VERSION){
				if($protocol < self::PROTOCOL_VERSION) $this->logger->warning("Outdated server!");
				if($protocol > self::PROTOCOL_VERSION) $this->logger->warning("Outdated client!");
				return false;
			}
			return true;
		}

		return false;
	}

	public function disconnect(){
		if($this->socket){
			fclose($this->socket);
		}
	}

	public function isConnected(){
		return $this->authorized;
	}

	public function getRemoteLogger(){
		if(!$this->isConnected()) return false;

		// send command packet.
		$this->writePacket(self::PACKET_LOGGER, self::SERVERDATA_LOGGER, "");
		// get response.
		$pk = $this->readPacket();
		if($pk['id'] == self::PACKET_LOGGER){
			if($pk['type'] == self::SERVERDATA_RESPONSE_VALUE){
				if($pk["body"] != ""){
					$this->lastResponse .= "\n" . $pk['body'];
					return $pk['body'];
				}
			}
		}

		return false;
	}

	public function sendCommand($command, $noResponse = false){
		if(!$this->isConnected()) return false;

		// send command packet.
		$this->writePacket(self::PACKET_COMMAND, self::SERVERDATA_EXECCOMMAND, $command);

		if(!$noResponse){
			// get response.
			$pk = $this->readPacket();
			if($pk['id'] == self::PACKET_COMMAND){
				if($pk['type'] == self::SERVERDATA_RESPONSE_VALUE){
					$this->lastResponse = $pk['body'];
					return $pk['body'];
				}
			}
		}
		return false;
	}

	private function getRemoteProtocol(){
		$this->writePacket(self::PACKET_PROTOCOL_CHECK, self::SERVERDATA_PROTOCOL, self::PROTOCOL_VERSION);
		$pk = $this->readPacket();

		if($pk['type'] == self::SERVERDATA_RESPONSE_VALUE){
			if($pk['id'] == self::PACKET_PROTOCOL_CHECK){
				return $pk["body"];
			}
		}

		$this->disconnect();
		return false;
	}

	private function authorize(){
		$this->writePacket(self::PACKET_AUTHORIZE, self::SERVERDATA_AUTH, $this->password);
		$pk = $this->readPacket();

		if($pk['type'] == self::SERVERDATA_AUTH_RESPONSE){
			if($pk['id'] == self::PACKET_AUTHORIZE){
				$this->logger->notice("Login success!");
				// $this->logger->info($pk["body"],"RCON");
				$this->authorized = true;
				return true;
			}
		}

		$this->disconnect();
		return false;
	}

	/**
	 * Writes a packet to the socket stream..
	 */
	private function writePacket($id, $type, $body){
		/*
		Size			32-bit little-endian Signed Integer	 	Varies, see below.
		ID				32-bit little-endian Signed Integer		Varies, see below.
		Type			32-bit little-endian Signed Integer		Varies, see below.
		Body			Null-terminated ASCII String			Varies, see below.
		Empty String	Null-terminated ASCII String			0x00
		*/

		try{
			//create packet
			$packet = pack("VV", $id, $type);
			$packet = $packet . $body . "\x00";
			$packet = $packet . "\x00";

			// get packet size.
			$size = strlen($packet);

			// attach size to packet.
			$packet = pack("V", $size) . $packet;

			// write packet.
			fwrite($this->socket, $packet, strlen($packet));
		}catch(Throwable $e){
			$this->logger->error("An error occurred while writing packet");
			exit(1);
		}
	}

	private function readPacket(){
		try{
			//get packet size.
			$sizeData = fread($this->socket, 4);
			$sizePack = unpack("V1size", $sizeData);
			$size = $sizePack['size'];

			// if size is > 4096, the response will be in multiple packets.
			// this needs to be address. get more info about multi-packet responses
			// from the RCON protocol specification at
			// https://developer.valvesoftware.com/wiki/Source_RCON_Protocol
			// currently, this script does not support multi-packet responses.

			$packetData = fread($this->socket, $size);
			$packetPack = unpack("V1id/V1type/a*body", $packetData);

			return $packetPack;
		}catch(Throwable $e){
			$this->logger->error("An error occurred while writing packet");
			exit(1);
		}
	}
}

abstract class Terminal{
	public static $FORMAT_BOLD = "";
	public static $FORMAT_OBFUSCATED = "";
	public static $FORMAT_ITALIC = "";
	public static $FORMAT_UNDERLINE = "";
	public static $FORMAT_STRIKETHROUGH = "";

	public static $FORMAT_RESET = "";

	public static $COLOR_BLACK = "";
	public static $COLOR_DARK_BLUE = "";
	public static $COLOR_DARK_GREEN = "";
	public static $COLOR_DARK_AQUA = "";
	public static $COLOR_DARK_RED = "";
	public static $COLOR_PURPLE = "";
	public static $COLOR_GOLD = "";
	public static $COLOR_GRAY = "";
	public static $COLOR_DARK_GRAY = "";
	public static $COLOR_BLUE = "";
	public static $COLOR_GREEN = "";
	public static $COLOR_AQUA = "";
	public static $COLOR_RED = "";
	public static $COLOR_LIGHT_PURPLE = "";
	public static $COLOR_YELLOW = "";
	public static $COLOR_WHITE = "";

	private static $formattingCodes = null;

	public static function hasFormattingCodes(){
		if(self::$formattingCodes === null){
			$opts = getopt("", ["enable-ansi", "disable-ansi"]);
			if(isset($opts["disable-ansi"])){
				self::$formattingCodes = false;
			}else{
				self::$formattingCodes = ((getenv("TERM") != "" and (!function_exists("posix_ttyname") or !defined("STDOUT") or posix_ttyname(STDOUT) !== false)) or isset($opts["enable-ansi"]));
			}
		}

		return self::$formattingCodes;
	}

	protected static function getFallbackEscapeCodes(){
		self::$FORMAT_BOLD = "\x1b[1m";
		self::$FORMAT_OBFUSCATED = "";
		self::$FORMAT_ITALIC = "\x1b[3m";
		self::$FORMAT_UNDERLINE = "\x1b[4m";
		self::$FORMAT_STRIKETHROUGH = "\x1b[9m";

		self::$FORMAT_RESET = "\x1b[m";

		self::$COLOR_BLACK = "\x1b[38;5;16m";
		self::$COLOR_DARK_BLUE = "\x1b[38;5;19m";
		self::$COLOR_DARK_GREEN = "\x1b[38;5;34m";
		self::$COLOR_DARK_AQUA = "\x1b[38;5;37m";
		self::$COLOR_DARK_RED = "\x1b[38;5;124m";
		self::$COLOR_PURPLE = "\x1b[38;5;127m";
		self::$COLOR_GOLD = "\x1b[38;5;214m";
		self::$COLOR_GRAY = "\x1b[38;5;145m";
		self::$COLOR_DARK_GRAY = "\x1b[38;5;59m";
		self::$COLOR_BLUE = "\x1b[38;5;63m";
		self::$COLOR_GREEN = "\x1b[38;5;83m";
		self::$COLOR_AQUA = "\x1b[38;5;87m";
		self::$COLOR_RED = "\x1b[38;5;203m";
		self::$COLOR_LIGHT_PURPLE = "\x1b[38;5;207m";
		self::$COLOR_YELLOW = "\x1b[38;5;227m";
		self::$COLOR_WHITE = "\x1b[38;5;231m";
	}

	public static function init(){
		if(!self::hasFormattingCodes()){
			return;
		}
		self::getFallbackEscapeCodes();
	}
}

/**
 * Class used to handle Minecraft chat format, and convert it to other formats like ANSI or HTML
 */
abstract class TextFormat{
	const ESCAPE = "\xc2\xa7"; //§

	const BLACK = TextFormat::ESCAPE . "0";
	const DARK_BLUE = TextFormat::ESCAPE . "1";
	const DARK_GREEN = TextFormat::ESCAPE . "2";
	const DARK_AQUA = TextFormat::ESCAPE . "3";
	const DARK_RED = TextFormat::ESCAPE . "4";
	const DARK_PURPLE = TextFormat::ESCAPE . "5";
	const GOLD = TextFormat::ESCAPE . "6";
	const GRAY = TextFormat::ESCAPE . "7";
	const DARK_GRAY = TextFormat::ESCAPE . "8";
	const BLUE = TextFormat::ESCAPE . "9";
	const GREEN = TextFormat::ESCAPE . "a";
	const AQUA = TextFormat::ESCAPE . "b";
	const RED = TextFormat::ESCAPE . "c";
	const LIGHT_PURPLE = TextFormat::ESCAPE . "d";
	const YELLOW = TextFormat::ESCAPE . "e";
	const WHITE = TextFormat::ESCAPE . "f";

	const OBFUSCATED = TextFormat::ESCAPE . "k";
	const BOLD = TextFormat::ESCAPE . "l";
	const STRIKETHROUGH = TextFormat::ESCAPE . "m";
	const UNDERLINE = TextFormat::ESCAPE . "n";
	const ITALIC = TextFormat::ESCAPE . "o";
	const RESET = TextFormat::ESCAPE . "r";

	/**
	 * Splits the string by Format tokens
	 *
	 * @param string $string
	 *
	 * @return array
	 */
	public static function tokenize($string){
		return preg_split("/(" . TextFormat::ESCAPE . "[0123456789abcdefklmnor])/", $string, -1, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
	}

	/**
	 * Cleans the string from Minecraft codes and ANSI Escape Codes
	 *
	 * @param string $string
	 * @param bool   $removeFormat
	 *
	 * @return mixed
	 */
	public static function clean($string, $removeFormat = true){
		if($removeFormat){
			return str_replace(TextFormat::ESCAPE, "", preg_replace(["/" . TextFormat::ESCAPE . "[0123456789abcdefklmnor]/", "/\x1b[\\(\\][[0-9;\\[\\(]+[Bm]/"], "", $string));
		}
		return str_replace("\x1b", "", preg_replace("/\x1b[\\(\\][[0-9;\\[\\(]+[Bm]/", "", $string));
	}

	/**
	 * Returns a string with colorized ANSI Escape codes
	 *
	 * @param $string
	 *
	 * @return string
	 */
	public static function toANSI($string){
		if(!is_array($string)){
			$string = self::tokenize($string);
		}

		$newString = "";
		foreach($string as $token){
			switch($token){
				case TextFormat::BOLD:
					$newString .= Terminal::$FORMAT_BOLD;
					break;
				case TextFormat::OBFUSCATED:
					$newString .= Terminal::$FORMAT_OBFUSCATED;
					break;
				case TextFormat::ITALIC:
					$newString .= Terminal::$FORMAT_ITALIC;
					break;
				case TextFormat::UNDERLINE:
					$newString .= Terminal::$FORMAT_UNDERLINE;
					break;
				case TextFormat::STRIKETHROUGH:
					$newString .= Terminal::$FORMAT_STRIKETHROUGH;
					break;
				case TextFormat::RESET:
					$newString .= Terminal::$FORMAT_RESET;
					break;

				//Colors
				case TextFormat::BLACK:
					$newString .= Terminal::$COLOR_BLACK;
					break;
				case TextFormat::DARK_BLUE:
					$newString .= Terminal::$COLOR_DARK_BLUE;
					break;
				case TextFormat::DARK_GREEN:
					$newString .= Terminal::$COLOR_DARK_GREEN;
					break;
				case TextFormat::DARK_AQUA:
					$newString .= Terminal::$COLOR_DARK_AQUA;
					break;
				case TextFormat::DARK_RED:
					$newString .= Terminal::$COLOR_DARK_RED;
					break;
				case TextFormat::DARK_PURPLE:
					$newString .= Terminal::$COLOR_PURPLE;
					break;
				case TextFormat::GOLD:
					$newString .= Terminal::$COLOR_GOLD;
					break;
				case TextFormat::GRAY:
					$newString .= Terminal::$COLOR_GRAY;
					break;
				case TextFormat::DARK_GRAY:
					$newString .= Terminal::$COLOR_DARK_GRAY;
					break;
				case TextFormat::BLUE:
					$newString .= Terminal::$COLOR_BLUE;
					break;
				case TextFormat::GREEN:
					$newString .= Terminal::$COLOR_GREEN;
					break;
				case TextFormat::AQUA:
					$newString .= Terminal::$COLOR_AQUA;
					break;
				case TextFormat::RED:
					$newString .= Terminal::$COLOR_RED;
					break;
				case TextFormat::LIGHT_PURPLE:
					$newString .= Terminal::$COLOR_LIGHT_PURPLE;
					break;
				case TextFormat::YELLOW:
					$newString .= Terminal::$COLOR_YELLOW;
					break;
				case TextFormat::WHITE:
					$newString .= Terminal::$COLOR_WHITE;
					break;
				default:
					$newString .= $token;
					break;
			}
		}

		return $newString;
	}

}

interface LogLevel{
	const EMERGENCY = "emergency";
	const ALERT = "alert";
	const CRITICAL = "critical";
	const ERROR = "error";
	const WARNING = "warning";
	const NOTICE = "notice";
	const INFO = "info";
	const DEBUG = "debug";
}

class MainLogger extends \Thread{
	protected $shutdown;
	protected $logDebug = false;

	/** @var MainLogger */
	public static $logger = null;

	/**
	 * @throws \RuntimeException
	 */
	public function __construct(){
		if(static::$logger instanceof MainLogger){
			throw new \RuntimeException("MainLogger has been already created");
		}
		$this->start();
	}

	/**
	 * @return MainLogger
	 */
	public static function getLogger(){
		return static::$logger;
	}

	public function emergency($message, $name = "EMERGENCY"){
		$this->send($message, \LogLevel::EMERGENCY, $name, TextFormat::RED);
	}

	public function alert($message, $name = "ALERT"){
		$this->send($message, \LogLevel::ALERT, $name, TextFormat::RED);
	}

	public function critical($message, $name = "CRITICAL"){
		$this->send($message, \LogLevel::CRITICAL, $name, TextFormat::RED);
	}

	public function error($message, $name = "ERROR"){
		$this->send($message, \LogLevel::ERROR, $name, TextFormat::DARK_RED);
	}

	public function warning($message, $name = "WARNING"){
		$this->send($message, \LogLevel::WARNING, $name, TextFormat::YELLOW);
	}

	public function notice($message, $name = "NOTICE"){
		$this->send($message, \LogLevel::NOTICE, $name, TextFormat::AQUA);
	}

	public function info($message, $name = "INFO", $color = TextFormat::WHITE){
		$this->send($message, \LogLevel::INFO, $name, $color);
	}

	public function debug($message, $name = "DEBUG"){
		if($this->logDebug === false){
			return;
		}
		$this->send($message, \LogLevel::DEBUG, $name, TextFormat::GRAY);
	}

	/**
	 * @param bool $logDebug
	 */
	public function setLogDebug($logDebug){
		$this->logDebug = (bool) $logDebug;
	}

	public function logException(\Throwable $e, $trace = null){
		//TODO
	}

	public function log($level, $message){
		switch($level){
			case LogLevel::EMERGENCY:
				$this->emergency($message);
				break;
			case LogLevel::ALERT:
				$this->alert($message);
				break;
			case LogLevel::CRITICAL:
				$this->critical($message);
				break;
			case LogLevel::ERROR:
				$this->error($message);
				break;
			case LogLevel::WARNING:
				$this->warning($message);
				break;
			case LogLevel::NOTICE:
				$this->notice($message);
				break;
			case LogLevel::INFO:
				$this->info($message);
				break;
			case LogLevel::DEBUG:
				$this->debug($message);
				break;
		}
	}

	public function shutdown(){
		$this->shutdown = true;
	}

	protected function send($message, $level, $prefix, $color){
		$now = time();

		$message = TextFormat::toANSI(TextFormat::AQUA . "[" . date("H:i:s", $now) . "] " . TextFormat::RESET . $color . "[" . $prefix . "]" . " " . $message . TextFormat::RESET);
		$cleanMessage = TextFormat::clean($message);

		if(!Terminal::hasFormattingCodes()){
			echo $cleanMessage . PHP_EOL;
		}else{
			echo $message . PHP_EOL;
		}

	}

	public function run(){
		$this->shutdown = false;
	}
}

class GeniRCONClient{
	const VER = "v1.0.3 alpha";

	/** @var ConsoleDaemon */
	private $console = null;
	/** @var GeniRCON */
	private $rcon = null;
	private $isRunning = true;
	/** @var MainLogger */
	private $logger = null;
	private $info = [];
	private $ticks = 0;
	private $lookup = [];

	public function __construct(){
		Terminal::init();
		$this->logger = new MainLogger();
		$this->logger->info("GeniRCON Client " . TextFormat::GREEN . self::VER);
		$this->logger->info("GeniRCON Protocol Version: " . TextFormat::LIGHT_PURPLE . GeniRCON::PROTOCOL_VERSION);
		$this->logger->info("Initializing ConsoleDaemon ...");
		$this->console = new ConsoleDaemon();
		$this->logger->info("Done! For help, type 'help'");
		$this->tickProcessor();
	}

	public function tickProcessor(){
		while($this->isRunning){
			$this->ticks++;
			$cmd = $this->console->getLine();
			if($cmd != null){
				$this->dispatchCommand($cmd);
			}
			if($this->rcon != null){
				$this->rcon->getRemoteLogger();
				$res = $this->rcon->getResponse();
				if($res != null){
					$res = explode("\n", $res);
					foreach($res as $line){
						if(trim($line) != "") {
							$j = explode("|", $line);
							if(count($j) >= 3){
								$color = array_shift($j);
								$prefix = array_shift($j);
								$line = implode("|", $j);
							}else{
								$color = TextFormat::WHITE;
								$prefix = "INFO";
							}
							$this->logger->info($line, "RCON / $prefix", $color);
						}
					}
				}
				sleep(0.01);
			}
		}
	}

	private function lookupAddress($address) {
		//IP address
		if (preg_match("/^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$/", $address) > 0) {
			return $address;
		}

		$address = strtolower($address);

		if (isset($this->lookup[$address])) {
			return $this->lookup[$address];
		}

		$host = gethostbyname($address);
		if ($host === $address) {
			return null;
		}

		$this->lookup[$address] = $host;
		return $host;
	}

	public function closeSession(){
		if($this->rcon != null){
			$this->logger->info("Disconnecting from " . $this->info[0] . ":" . $this->info[1]);
			$this->rcon->disconnect();
		}
	}

	public function dispatchCommand(string $cmd){
		$c = explode(" ", $cmd);
		$co = array_shift($c);
		switch(strtolower($co)){
			case "disconnect":
				if($this->rcon != null){
					$this->logger->notice("Disconnecting from " . $this->info[0] . ":" . $this->info[1]);
					$this->rcon->disconnect();
					$this->rcon = null;
					$this->logger->info("Disconnected from " . $this->info[0] . ":" . $this->info[1]);
				}else $this->logger->warning("You haven't connected to any server yet");

				break;
			case "version":
				if($this->rcon == null){
					$this->logger->info(TextFormat::AQUA . "GeniRCON Client" . TextFormat::WHITE . " [version: " . TextFormat::LIGHT_PURPLE . self::VER . TextFormat::WHITE . "] (protocol version: " . TextFormat::GOLD . GeniRCON::PROTOCOL_VERSION . TextFormat::WHITE . ")");
				}else $this->rcon->sendCommand($cmd);

				break;
			case "exit":
				$this->logger->info("Stopping GeniRCON Client ...");
				$this->closeSession();
				$this->console->shutdown();
				$this->console->quit();
				$this->logger->shutdown();
				$this->isRunning = false;
				echo("GeniRCON Client has stopped" . PHP_EOL);
				exit(0);

				break;
			case "help":
				if($this->rcon == null){
					$commandList = [
						"connect" => ["connect <host> <port> <password> <timeout>", "Connect to a server"],
						"disconnect" => ["disconnect", "Disconnect from current session"],
						"exit" => ["exit", "Shutdown this program and exit"],
						"version" => ["version", "Gets the version of this program"]
					];
					if(count($c) == 0){
						$this->logger->info("------- Help -------");
						foreach($commandList as $k => $cmd){
							$this->logger->info(TextFormat::DARK_GREEN . $k . ": " . TextFormat::WHITE . $cmd[1]);
						}
					}else{
						if(isset($commandList[$c[0]])){
							$this->logger->info(TextFormat::YELLOW . "-------" . TextFormat::WHITE . " Help: " . $c[0] . " " . TextFormat::YELLOW . "-------");
							$this->logger->info(TextFormat::GOLD . "Description: " . TextFormat::WHITE . $commandList[$c[0]][1]);
							$this->logger->info(TextFormat::GOLD . "Usage: " . TextFormat::WHITE . $commandList[$c[0]][0]);
						}else $this->logger->alert("No help for " . $c[0]);
					}
				}else $this->rcon->sendCommand($cmd);

				break;
			case "connect":
				$info = $c;
				if(count($info) != 4){
					$this->logger->warning("Wrong format! Please try again");
				}else{
					$this->info = $info;
					$this->rcon = new GeniRCON($this->logger, $this->lookupAddress($info[0]), $info[1], $info[2], $info[3]);
					$this->logger->notice("GeniRCON session has been created!");
					$this->logger->info("Connecting to " . $info[0] . ":" . $info[1] . " ...");
					if($this->rcon->connect()){
						$this->logger->info("Connected!");
					}else{
						$this->logger->error("Failed to connect to " . $info[0] . ":" . $info[1]);
						$this->rcon = null;
					}
				}

				break;
			case "stop":
				if($this->rcon != null){
					$this->rcon->sendCommand($cmd, true);
					$this->closeSession();
				}else $this->logger->alert("Command not found. Type 'help' for help");
				break;
			default:
				if($this->rcon == null) $this->logger->alert("Command not found. Type 'help' for help");
				else $this->rcon->sendCommand($cmd);
				break;
		}
	}
}

new GeniRCONClient();
