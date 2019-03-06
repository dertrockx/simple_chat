#!/bin/bash

echo -e "\e[32mAdding files..."
echo -e "\e[33m"
git add . 

echo -e "\e[32mCommiting..."
echo -e "\e[33m"
git commit

echo -e "\e[32mPusing files..."
echo -e "\e[33m"
git push -u origin master
echo -e "\e[32mDone pushing."
