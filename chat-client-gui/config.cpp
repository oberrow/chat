#include "config.hpp"
#include <string>
#include <ranges>

Config::Config()
{}

Config::Config(std::istream& is) { Parse(is); }

bool Config::Parse(std::istream& is)
{
	constexpr size_t npos = (size_t)~0;
	size_t pos = 0;
	std::string str;
	std::string type, name, value;
	while (std::getline(is, str))
	{
		std::string cpyStr = str;
		pos = cpyStr.find(' ');
		type = cpyStr.substr(0, pos);
		cpyStr.erase(0, pos);
		while (cpyStr.front() == 0x20) cpyStr.erase(0, 1);
		pos = cpyStr.find(' ');
		value = cpyStr.substr(pos, npos);
		std::erase(value, '=');
		while (value.front() == 0x20) value.erase(0, 1);
		std::reverse(cpyStr.begin(), cpyStr.end());
		name = cpyStr.substr(cpyStr.length() - pos);
		std::reverse(name.begin(), name.end());
		if (type == "int")
		{
			while (value.front() == ' ' || value.front() == '=') value.erase(0, 1);
		}
		Store st = { 0, "" };
		if (type == "double")
		{
			st.type = Store::type::basic_double;
			st.flt_Out = std::atof(value.c_str());
		}
		else if (type == "int")
		{
			st.type = Store::type::basic_int;
			st.int_Out = std::atoi(value.c_str());
		}
		else if(type == "string")
		{
			st.type = Store::type::basic_string;
			st.str_Out = value;
		}
		map.try_emplace(name, st);
	}
	return true;
}

bool Config::GetState() { return m_State; }

bool isNumber(const std::string& str)
{
	for (auto& ch : str)
	{
		if (!isNumber(ch)) return false;
	}
	return true;
}

bool isNumber(char ch)
{
	char num[11] = "0123456789";
	for (int i = 0; i < 11; i++)
	{
		if (ch == num[i]) return true;
	}
	return false;
}

bool isDecimalNumber(const std::string& s)
{
	char num[12] = "0123456789.";
	int index = 0;
	for (const char& i : s)
	{
		if (i == num[index]) return true;
		index++;
	}
	return false;
}