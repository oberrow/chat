#pragma once
#include <iostream>
#include <string>
#include <unordered_map>

struct Store
{
	enum class type
	{
		invalid		 = -1,   
		basic_int    = sizeof(int),
		basic_string = sizeof(std::string),
		basic_double = sizeof(double)
	};
	int int_Out = 0;
	std::string str_Out = "";
	double flt_Out = 0.0;
	type type = type::invalid;
	operator std::string() const { return str_Out; }
	operator int()		   const { return int_Out; }
	operator double()	   const { return flt_Out; }
};

bool isNumber(const std::string& str);
bool isNumber(char ch);
bool isDecimalNumber(const std::string& s);

class Config
{
public:
	std::unordered_map<std::string, Store> map;
	Config();
	Config(std::istream& is);
	bool Parse(std::istream& is);
	bool GetState();
private:
	bool m_State = true;
};