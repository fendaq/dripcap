#ifndef FILTER_HPP
#define FILTER_HPP

#include <v8.h>
#include <functional>

class Packet;

struct FilterResult {
  FilterResult(v8::Local<v8::Value> value,
               v8::Local<v8::Value> parent = v8::Local<v8::Value>())
      : value(value), parent(parent) {}
  v8::Local<v8::Value> value;
  v8::Local<v8::Value> parent;
};

typedef std::function<FilterResult(Packet *)> FilterFunc;

FilterFunc makeFilter(const std::string &jsonstr);

#endif
