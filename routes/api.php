<?php

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


Route::post('login', [Controller::class, 'login']);
Route::post('register', [Controller::class, 'register']);
Route::post('verifyOtp', [Controller::class, 'verifyOtp']);
Route::post('confirmPass', [Controller::class, 'confirmPass']);
Route::post('addExpenses', [Controller::class, 'createExpenses']);