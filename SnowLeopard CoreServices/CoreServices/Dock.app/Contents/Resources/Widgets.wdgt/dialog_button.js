/*
Copyright © 2005, Apple Computer, Inc.  All rights reserved.
NOTE:  Use of this source code is subject to the terms of the Software
License Agreement for Mac OS X, which accompanies the code.  Your use
of this source code signifies your agreement to such license terms and
conditions.  Except as expressly granted in the Software License Agreement
for Mac OS X, no other copyright, patent, or other intellectual property
license or right is granted, either expressly or by implication, by Apple.
*/

function createDialogButton (div, title, onaction, minwidth)
{
	div.style.height = "24px";
	div.style.appleDashboardRegion = 'dashboard-region(control rectangle)';
	var element = document.createElement ('img');
	element.src = 'Images/Dialog/button_left.png';
	element.style.verticalAlign = "bottom";
	div.appendChild (element);
	
	element = document.createElement('div');
	element.setAttribute ("style", 'display:inline-block;vertical-align:bottom;text-align:center;line-height:24px;background:url(Images/Dialog/button_center.png) repeat-x top left;');	
	div.appendChild (element);
	element.innerHTML = title;
	if (minwidth !== undefined)
	{
		element.style.minWidth = (minwidth - 26) + "px"; // 26 hard code size of left and right
	}
	
	element = document.createElement ('img');
	element.src = 'Images/Dialog/button_right.png';
	element.style.verticalAlign = "bottom";
	div.appendChild (element);
	
	div.setAttribute ("onmousedown", "dialogButtonMouseDownHandler(event, this);");
	div.buttonInside = true;
	div.buttonAction = onaction;
	
	// force the images to load.
	var img = new Image;
	img.src = 'Images/Dialog/button_left_pressed.png';
	var img = new Image;
	img.src = 'Images/Dialog/button_center_pressed.png';
	var img = new Image;
	img.src = 'Images/Dialog/button_right_pressed.png';
}

// do not call the following methods directly
var dialogButtonCurrentMouseDownButton = null;
function dialogButtonMouseDownHandler(event, div)
{
	div.childNodes[0].src = 'Images/Dialog/button_left_pressed.png';
	div.childNodes[1].style.backgroundImage = 'url(Images/Dialog/button_center_pressed.png)';
	div.childNodes[2].src = 'Images/Dialog/button_right_pressed.png';
	
	document.addEventListener("mousemove", dialogButtonMouseMoveHandler, true);
	document.addEventListener("mouseup", dialogButtonMouseUpHandler, true);
	div.addEventListener("mouseover", dialogButtonMouseOverHandler, true);
	div.addEventListener("mouseout", dialogButtonMouseOutHandler, true);
	
	div.buttonInside = true;
	div.theClass = div.getAttribute('class');
	div.setAttribute('class','dialog-button dialog-button-down');
	dialogButtonCurrentMouseDownButton = div;
	
	event.stopPropagation();
	event.preventDefault();

}

function dialogButtonMouseMoveHandler (event)
{
	event.stopPropagation();
	event.preventDefault();
}

function dialogButtonMouseOverHandler (event)
{
	dialogButtonCurrentMouseDownButton.childNodes[0].src = 'Images/Dialog/button_left_pressed.png';
	dialogButtonCurrentMouseDownButton.childNodes[1].style.backgroundImage = 'url(Images/Dialog/button_center_pressed.png)';
	dialogButtonCurrentMouseDownButton.childNodes[2].src = 'Images/Dialog/button_right_pressed.png';
	
	dialogButtonCurrentMouseDownButton.buttonInside = true;
	dialogButtonCurrentMouseDownButton.setAttribute('class','dialog-button dialog-button-down');
	event.stopPropagation();
	event.preventDefault();
}

function dialogButtonMouseOutHandler (event)
{
	dialogButtonCurrentMouseDownButton.childNodes[0].src = 'Images/Dialog/button_left.png';
	dialogButtonCurrentMouseDownButton.childNodes[1].style.backgroundImage = 'url(Images/Dialog/button_center.png)';
	dialogButtonCurrentMouseDownButton.childNodes[2].src = 'Images/Dialog/button_right.png';

	dialogButtonCurrentMouseDownButton.buttonInside = false;
	dialogButtonCurrentMouseDownButton.setAttribute('class',dialogButtonCurrentMouseDownButton.theClass);

	event.stopPropagation();
	event.preventDefault();
}

function dialogButtonMouseUpHandler (event)
{
	dialogButtonCurrentMouseDownButton.childNodes[0].src = 'Images/Dialog/button_left.png';
	dialogButtonCurrentMouseDownButton.childNodes[1].style.backgroundImage = 'url(Images/Dialog/button_center.png)';
	dialogButtonCurrentMouseDownButton.childNodes[2].src = 'Images/Dialog/button_right.png';

	// callback to the client
	document.removeEventListener("mousemove", dialogButtonMouseMoveHandler, true);
	document.removeEventListener("mouseup", dialogButtonMouseUpHandler, true);	
	dialogButtonCurrentMouseDownButton.removeEventListener("mouseover", dialogButtonMouseOverHandler, true);
	dialogButtonCurrentMouseDownButton.removeEventListener("mouseout", dialogButtonMouseOutHandler, true);

	dialogButtonCurrentMouseDownButton.setAttribute('class',dialogButtonCurrentMouseDownButton.theClass);
		
	event.stopPropagation();
	event.preventDefault();
		
	if (dialogButtonCurrentMouseDownButton.buttonAction && dialogButtonCurrentMouseDownButton.buttonInside)
	{
		dialogButtonCurrentMouseDownButton.buttonAction();
	}
	
	dialogButtonCurrentMouseDownButton = null;
}
