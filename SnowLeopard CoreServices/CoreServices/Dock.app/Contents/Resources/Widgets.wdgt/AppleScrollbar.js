/*
Copyright © 2005, Apple Computer, Inc.  All rights reserved.
NOTE:  Use of this source code is subject to the terms of the Software
License Agreement for Mac OS X, which accompanies the code.  Your use
of this source code signifies your agreement to such license terms and
conditions.  Except as expressly granted in the Software License Agreement
for Mac OS X, no other copyright, patent, or other intellectual property
license or right is granted, either expressly or by implication, by Apple.
*/

/*
 * AppleScrollbar Constructor
 *     frame is the element which encloses both the content and the scrollbar.
 *   content is the element containing the display to be scrolled.
 * scrollbar is the element representing the scrollbar.
 */
function AppleScrollbar(frame, content, scrollbar)
{
	/* Objects */
	this.frame = frame;
	this.content = content;
	this.scrollbar = scrollbar;
	this.scrollTrack = null;
	this.scrollThumb = null;
	this.content_comp_style = null;
	
	this.scrollbar_padding = -1;
	
	/* public properties */
	// note that there are setter functions for these
	this.autohideScrollbar = false;
	this.imgScrollWidth = 19;
	this.imgScrollTrackTop_path = "Images/top_scroll_track.png";
	this.imgScrollTrackTop_height = 17;
	this.imgScrollTrackMiddle_path = "Images/mid_scroll_track.png";
	this.imgScrollTrackBottom_path = "Images/bottom_scroll_track.png";
	this.imgScrollTrackBottom_height = 17;
	this.imgScrollThumbTop_path = "Images/scroll_bar_top.png";
	this.imgScrollThumbTop_height = 9;
	this.imgScrollThumbMiddle_path = "Images/scroll_bar_mid.png";
	this.imgScrollThumbBottom_path = "Images/scroll_bar_bottom.png";
	this.imgScrollThumbBottom_height = 9;
	
	/* Dimensions */
	// these only need to be set during refresh()
	this.scrollbar_offset_y = 0;
	this.content_height = 0;
	this.view_height = 0;
	this.scrollbar_height = 0;
	this.num_scrollable_pixels = 0;
	this.thumb_height = 0;
	this.view_to_content_ratio = 1.0;
	
	// these change as the content is scrolled
	this.content_top = 0;
	this.thumb_top = this.scrollbar_padding;
	
	this.thumb_start_y = -1;
	this.scroll_thumb_start_pos = this.scrollbar_padding;
	
	this.track_mouse_y = 0;
	this.track_timer = null;
	this.track_scrolling = false;
	
	// mousewheel const's
	this.mousewheel_scrollpixels = 11; // XXX Get from defaults?
	this.mousewheel_deltadivisor = 75; // XXX Get from defaults?

	// For JavaScript event handlers
	var self = this;
	
	/*
	 * Privileged methods
	 * This event handlers need to be here because within an event handler,
	 * "this" refers to the element which called the event, rather than the 
	 * class instance.
	 */
	
	/*********************
	 * Thumb scroll events
	 */
	this.mousedownThumb = function(event)
	{
		// temporary event listeners
		document.addEventListener("mousemove", self.mousemoveThumb, true);
		document.addEventListener("mouseup", self.mouseupThumb, true);
		document.addEventListener("mouseover", self.mouseoverThumb, true);
		
		self.thumb_start_y = event.y;
		
		self.scroll_thumb_start_pos = parseInt(document.defaultView.getComputedStyle(self.scrollThumb,'').getPropertyValue("top"));

		event.stopPropagation();
		event.preventDefault();

	}
	
	this.mouseoverThumb = function(event)
	{
		event.stopPropagation();
		event.preventDefault();
	}
	
	this.mousemoveThumb = function(event)
	{
		var deltaY = event.y - self.thumb_start_y;
		
		var new_pos = self.scroll_thumb_start_pos + deltaY;
		self.scrollContent(new_pos);
		
		event.stopPropagation();
		event.preventDefault();
	}
	
	this.mouseupThumb = function(event)
	{
		document.removeEventListener("mousemove", self.mousemoveThumb, true);
		document.removeEventListener("mouseup", self.mouseupThumb, true);
		document.removeEventListener("mouseover", self.mouseoverThumb, true);
		
		// reset the starting position
		self.thumb_start_y = -1;
		
		event.stopPropagation();
		event.preventDefault();
	}
	
	/*********************
	 * Track scroll events
	 */
	this.mousedownTrack = function(event)
	{
		self.track_mouse_y = parseInt(event.y) - self.scrollbar_offset_y;
		
		self.track_scrolling = true;
		
		// temporary event handlers
		self.scrollTrack.addEventListener("mousemove", self.mousemoveTrack, true);
		self.scrollTrack.addEventListener("mouseover", self.mouseoverTrack, true);
		self.scrollTrack.addEventListener("mouseout", self.mouseoutTrack, true);
		document.addEventListener("mouseup", self.mouseupTrack, false);

		self.trackScroll(self);
		self.track_timer = setInterval(self.trackScroll, 150, self); // XXX page skip pause

		event.stopPropagation();
		event.preventDefault();
	}
	
	this.mousemoveTrack = function(event)
	{
		self.track_mouse_y = parseInt(event.y) - self.scrollbar_offset_y;

		event.stopPropagation();
		event.preventDefault();
	}
	
	this.mouseoverTrack = function(event)
	{
		self.track_mouse_y = parseInt(event.y) - self.scrollbar_offset_y;
		self.track_scrolling = true;

		event.stopPropagation();
		event.preventDefault();
	}
	
	this.mouseoutTrack = function(event)
	{
		self.track_scrolling = false;

		event.stopPropagation();
		event.preventDefault();

	}
	
	this.mouseupTrack = function(event)
	{
		clearInterval(self.track_timer);
		
		self.track_scrolling = false;
		
		// clear temporary event handlers
		self.scrollTrack.removeEventListener("mousemove", self.mousemoveTrack, true);
		self.scrollTrack.removeEventListener("mouseover", self.mouseoverTrack, true);
		self.scrollTrack.removeEventListener("mouseout", self.mouseoutTrack, true);
		document.removeEventListener("mouseup", self.mouseupTrack, false);

		event.stopPropagation();
		event.preventDefault();
	}
	
	/*********************
	 * Scrollwheel events
	 */
	this.mousewheelScroll = function(event)
	{
		var scrollRatio = 0.0;
		if (self.view_height < self.content_height)
		{
			scrollRatio = parseFloat(self.mousewheel_scrollpixels / self.content_height);
		}
		
		var wheelDelta = event.wheelDelta;

		if (wheelDelta < 0)
			wheelDelta = Math.floor(wheelDelta / self.mousewheel_deltadivisor);
		else if (wheelDelta > 0)
			wheelDelta = Math.ceil(wheelDelta / self.mousewheel_deltadivisor);
		
		var deltaScroll = (Math.ceil(self.scrollbar_height * scrollRatio) * parseInt(wheelDelta));
		
		self.scrollContentByDelta(-deltaScroll);
		
		event.stopPropagation();
		event.preventDefault();
	}
	
	this.init();
}

/*
 * init() member function
 * Initialize the scrollbar.
 * You do not need to call this directly, it will be called when necessary.
 * You probably want to be calling refresh().
 * pre: this.frame, this.content, this.scrollbar
 * post: this.scrollThumb, this.scrollTrack + event handlers
 */
AppleScrollbar.prototype.init = function()
{
	var style = null;
	var element = null;
	
	// Set up the styles for the frame and content elements just to be certain
	style = this.frame.style;
	//style.position = "absolute";
	style.overflow = "hidden";
	
	style = this.content.style;
	//style.position = "absolute";
	style.top = "0px";
	style.right = this.imgScrollWidth + "px";
	
	// Scrollbar element
	style = this.scrollbar.style;
	style.position = "absolute";
	style.top = "0px";
	//style.right = "14px";
	style.bottom = "0px";
	style.width = this.imgScrollWidth + "px";
	style.appleDashboardRegion = "dashboard-region(control rectangle)";

	// Scrollbar Track
	this.scrollTrack = document.createElement("div");
	this.scrollbar.appendChild(this.scrollTrack);
	
	// Scrollbar Track Top
	element = document.createElement("img");
	element.src = this.imgScrollTrackTop_path;
	style = element.style;
	style.position = "absolute";
	style.top = "0px";
	//style.khtmlUserSelect = "none";
	this.scrollTrack.appendChild(element);
	
	// Scrollbar Track Middle
	element = document.createElement("div");
	style = element.style;
	style.position = "absolute";
	style.top = this.imgScrollTrackTop_height + "px";
	style.bottom = this.imgScrollTrackBottom_height + "px";
	style.width = this.imgScrollWidth + "px";
	style.background = "url(" + this.imgScrollTrackMiddle_path + ") repeat-y top left";
	this.scrollTrack.appendChild(element);
	
	// Scrollbar Track Bottom
	element = document.createElement("img");
	element.src = this.imgScrollTrackBottom_path;
	style = element.style;
	style.position = "absolute";
	style.bottom = "0px";
	//style.khtmlUserSelect = "none";
	this.scrollTrack.appendChild(element);
	
	// Scrollbar Thumb
	this.scrollThumb = document.createElement("div");
	style = this.scrollThumb.style;
	style.position = "absolute";
	style.top = this.scrollbar_padding + "px";
	style.left = "1px"; // offset, depends on track width
	style.height = "28px";  // default height
	this.scrollbar.appendChild(this.scrollThumb);
	
	// Scrollbar Thumb Top
	element = document.createElement("img");
	element.src = this.imgScrollThumbTop_path;
	style = element.style;
	style.position = "absolute";
	style.top = "0px";
	//style.khtmlUserSelect = "none";
	this.scrollThumb.appendChild(element);
	
	// Scrollbar Thumb Middle
	element = document.createElement("div");
	style = element.style;
	style.position = "absolute";
	style.top = this.imgScrollThumbTop_height + "px";
	style.width = this.imgScrollWidth + "px";
	style.bottom = this.imgScrollThumbBottom_height + "px";
	style.background = "url(" + this.imgScrollThumbMiddle_path + ") repeat-y top left";
	this.scrollThumb.appendChild(element);
	
	// Scrollbar Thumb Bottom
	element = document.createElement("img");
	element.src = this.imgScrollThumbBottom_path;
	style = element.style;
	style.position = "absolute";
	style.bottom = "0px";
	//style.khtmlUserSelect = "none";
	this.scrollThumb.appendChild(element);
	
	
	// Add event listeners
	this.scrollTrack.addEventListener("mousedown", this.mousedownTrack, true);
	this.scrollThumb.addEventListener("mousedown", this.mousedownThumb, true);
	this.frame.addEventListener("mousewheel", this.mousewheelScroll, false);
	this.scrollbar.addEventListener("mousewheel", this.mousewheelScroll, false);
		
	this.content_comp_style = document.defaultView.getComputedStyle(this.content, '');
	//this.content_top = this.content_comp_style ? parseInt(this.content_comp_style.getPropertyValue("top")) : 0;
	this.content_top = 0;
	
	this.refresh();
}

/*
 * refresh() member function
 * Refresh the current scrollbar position and size.
 * This should be called whenever the content element changes.
 * Call this to make the scrollbar appear after the widget has loaded and 
 * the AppleScrollbar object has been instantiated.
 */
AppleScrollbar.prototype.refresh = function()
{
	// get the scrollbar offset
	this.scrollbar_offset_y = this.findPosY(this.scrollbar);
	
	// get the current content area height and offset
	this.content_height = this.content_comp_style ? parseInt(this.content_comp_style.getPropertyValue("height")) : 0;
	
	// get the current actual frame height. Float because we divide.
	var style = document.defaultView.getComputedStyle(this.frame, '');
	this.view_height = style ? parseFloat(style.getPropertyValue("height")) : 0;
	style = document.defaultView.getComputedStyle(this.scrollbar, '');
	this.scrollbar_height = style ? parseInt(style.getPropertyValue("height")) : 0;
	
	this.view_to_content_ratio = 1.0;
	if (this.content_height >= this.view_height)
		this.view_to_content_ratio = this.view_height / this.content_height;
	
	if (this.view_to_content_ratio >= 1.0)
	{
		// hide the scrollbar, all content is visible
		if (this.autohideScrollbar)
			this.hideScrollbar();
		else
			this.scrollThumb.style.display = "none"; // just hide the thumb
		
		this.scrollContent(this.thumbPositionForPagePosition(this.content_top)); // make sure content matches thumb
	}
	else
	{
		this.thumb_height = Math.max(Math.round(this.scrollbar_height * this.view_to_content_ratio), 27); // XXX 27 is min thumb size
		this.num_scrollable_pixels = this.scrollbar_height - this.thumb_height - (2 * this.scrollbar_padding);
		
		this.scrollThumb.style.height = this.thumb_height + "px";
		
		this.scrollContent(this.thumbPositionForPagePosition(this.content_top)); // make sure content matches thumb
		
		this.showScrollbar();
	}
}

AppleScrollbar.prototype.automaticallyHideScrollbar = function(autohide)
{
	this.autohideScrollbar = autohide;
	
	// hide the scrollbar if necessary
	if (this.view_to_content_ratio >= 1.0)
	{
		if (autohide)
			this.hideScrollbar();
		else
			this.showScrollbar();
	}
}

AppleScrollbar.prototype.setScrollWidth = function(width)
{
	this.imgScrollWidth = width;
	
	if (this.scrollTrack)
	{
		this.scrollTrack.children[1].style.width = width + "px";
	}
	if (this.scrollThumb)
	{
		this.scrollThumb.children[1].style.width = width + "px";
	}
}

AppleScrollbar.prototype.setScrollTrackTop = function(imgpath, height)
{
	this.imgScrollTrackTop_path = imgpath;
	this.imgScrollTrackTop_height = height;
	if (this.scrollTrack)
	{
		this.scrollTrack.children[0].src = imgpath;
		this.scrollTrack.children[1].style.top = height + "px";
	}
}

AppleScrollbar.prototype.setScrollTrackMiddle = function(imgpath)
{
	this.imgScrollTrackMiddle_path = imgpath;
	if (this.scrollTrack)
	{
		this.scrollTrack.children[1].style.background = "url(" + imgpath + ") repeat-y top left";
	}
}

AppleScrollbar.prototype.setScrollTrackBottom = function(imgpath, height)
{
	this.imgScrollTrackBottom_path = imgpath;
	this.imgScrollTrackBottom_height = height;
	if (this.scrollTrack)
	{
		this.scrollTrack.children[2].src = imgpath;
		this.scrollTrack.children[1].style.bottom = height + "px";
	}
}

AppleScrollbar.prototype.setScrollThumbTop = function(imgpath, height)
{
	this.imgScrollThumbTop_path = imgpath;
	this.imgScrollThumbTop_height = height;
	if (this.scrollThumb)
	{
		this.scrollThumb.children[0].src = imgpath;
		this.scrollThumb.children[1].style.top = height + "px";
	}
}

AppleScrollbar.prototype.setScrollThumbMiddle = function(imgpath)
{
	this.imgScrollThumbMiddle_path = imgpath;
	if (this.scrollThumb)
	{
		this.scrollThumb.children[1].style.background = "url(" + imgpath + ") repeat-y top left";
	}
}

AppleScrollbar.prototype.setScrollThumbBottom = function(imgpath, height)
{
	this.imgScrollThumbBottom_path = imgpath;
	this.imgScrollThumbBottom_height = height;
	if (this.scrollThumb)
	{
		this.scrollThumb.children[2].src = imgpath;
		this.scrollThumb.children[1].style.bottom = height + "px";
	}
}

AppleScrollbar.prototype.hideScrollbar = function()
{
	this.scrollTrack.style.display = "none";
	this.scrollThumb.style.display = "none";
}

AppleScrollbar.prototype.showScrollbar = function()
{
	this.scrollTrack.style.display = "block";
	if (this.view_to_content_ratio >= 1.0)
		this.scrollThumb.style.display = "none";
	else
		this.scrollThumb.style.display = "block";
}

AppleScrollbar.prototype.pagePositionForThumbPosition = function(thumb_pos)
{
	// if we're currently displaying all content, we don't want it outside the view
	if (this.view_to_content_ratio >= 1.0)
	{
		return 0;
	}
	else
	{
		return -(thumb_pos - this.scrollbar_padding) * ((this.content_height - this.view_height) / this.num_scrollable_pixels);
	}
}

AppleScrollbar.prototype.thumbPositionForPagePosition = function(page_pos)
{
	// if we're currently displaying all content, we don't want it outside the view
	if (this.view_to_content_ratio >= 1.0)
	{
		return this.scrollbar_padding;
	}
	else
	{
		return this.scrollbar_padding - (page_pos / ((this.content_height - this.view_height) / this.num_scrollable_pixels));
	}
}

AppleScrollbar.prototype.findPosY = function(obj)
{
	var curtop = 0;
	while (obj.offsetParent)
	{
		curtop += obj.offsetTop;
		obj = obj.offsetParent;
	}
	return curtop;
}


/*****************
 * Thumb Scrolling
 */
AppleScrollbar.prototype.scrollContent = function(new_thumb_pos)
{
	if (new_thumb_pos < this.scrollbar_padding)
	{
		new_thumb_pos = this.scrollbar_padding;
	}
	else if (new_thumb_pos > this.num_scrollable_pixels)
	{
		new_thumb_pos = this.num_scrollable_pixels;
	}
	
	this.scrollThumb.style.top = new_thumb_pos + "px";
	this.thumb_top = new_thumb_pos;
	this.content_top = this.pagePositionForThumbPosition(new_thumb_pos);
	this.content.style.top = this.content_top + "px";
}

AppleScrollbar.prototype.scrollContentByDelta = function(deltaY)
{
	if (deltaY == 0)
		return;
	
	this.scrollContent(this.thumb_top + parseInt(deltaY));
}

/*****************
 * Track Scrolling
 */
AppleScrollbar.prototype.trackScroll = function(selfptr)
{
	// this is called from setInterval, so we need a ptr to this
	var self = this;
	if (selfptr)
		self = selfptr;
	
	if (!self.track_scrolling) return;
	
	self.content_top = parseInt(self.content_comp_style.getPropertyValue("top")); // XXX necessary?
	
	var deltaScroll = Math.round(self.scrollbar_height * self.view_to_content_ratio);
	
	if (self.track_mouse_y < parseInt(self.thumb_top))
		self.scrollContentByDelta(-deltaScroll);
	else if (self.track_mouse_y > (parseInt(self.thumb_top) + self.thumb_height))
		self.scrollContentByDelta(deltaScroll);
}
