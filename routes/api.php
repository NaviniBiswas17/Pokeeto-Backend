<?php

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


Route::post('login', [Controller::class, 'login']);
Route::post('loginGuest', [Controller::class, 'loginGuest']);
Route::post('sendOtp', [Controller::class, 'sendOtp']);
// Route::post('verifyOtp', [Controller::class, 'verifyOtp']);
// Route::post('confirmPass', [Controller::class, 'confirmPass']);


Route::post('addAccount', [Controller::class, 'addAccount']);
Route::post('getAccountList', [Controller::class, 'getAccountList']);
Route::post('getAccount', [Controller::class, 'getAccount']);
Route::post('addContributor', [Controller::class, 'addContributor']);
Route::post('getContributorList', [Controller::class, 'getContributorList']);
Route::post('getUserCategoryList', [Controller::class, 'getUserCategoryList']);
Route::post('addUserCategory', [Controller::class, 'addUserCategory']);
Route::post('getUserDetails', [Controller::class, 'getUserDetails']);
Route::post('updateUserSetting', [Controller::class, 'updateUserSetting']);
Route::post('getTransactionList', [Controller::class, 'getTransactionList']);
Route::post('addTransaction', [Controller::class, 'addTransaction']);
Route::post('getTransaction', [Controller::class, 'getTransaction']);
Route::post('deleteTransaction', [Controller::class, 'deleteTransaction']);
Route::post('editTransaction', [Controller::class, 'editTransaction']);
Route::post('addKid', [Controller::class, 'addKid']);
Route::post('addKidTask', [Controller::class, 'addKidTask']);
Route::post('getKidTask', [Controller::class, 'getKidTask']);
Route::post('addKidGoal', [Controller::class, 'addKidGoal']);
Route::post('getKidGoal', [Controller::class, 'getKidGoal']);
Route::post('getKidDetailList', [Controller::class, 'getKidDetailList']);


